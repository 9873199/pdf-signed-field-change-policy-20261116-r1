"""
Injectable field-change permission policies for incremental update analysis.

This module implements an opt-in, fail-closed layer on top of pyHanko's
regular difference analysis. It is intended for validators that need to
honour a *caller-supplied* list of form fields that may be filled in after
signing, instead of accepting any form fill operation that the (deliberately
permissive) default policy allows at
:attr:`~pyhanko.sign.diff_analysis.ModificationLevel.FORM_FILLING` level.

The model is as follows:

* The caller provides a :class:`FieldChangePermissionPolicy` that adjudicates
  changes to individual fields, based on the signature being validated, the
  revision being vetted and the fully qualified field name.
  :class:`WhitelistFieldChangePolicy` implements the common case where the
  caller simply supplies the complete set of field names that may be touched.
* :class:`FieldChangeRestrictedDiffPolicy` wraps another
  :class:`~pyhanko.sign.diff_analysis.DiffPolicy` (the default policy unless
  overridden) and intersects its verdict with the permission policy:
  a change is only ever accepted if *both* allow it. In particular, DocMDP
  and FieldMDP restrictions imposed by earlier signatures are still enforced
  by the wrapped policy and can never be relaxed by the permission policy.

On top of the wrapped policy's checks, the following rules are enforced
whenever this policy is in force:

* only changes to the value (``/V``) and normal appearance characteristics
  of **text fields that already existed at signing time** are acceptable;
* any change to the field tree structure is rejected: renaming fields,
  duplicate field names, reparenting/reordering fields, adding or deleting
  fields (including new signature fields) and replacing field objects;
* changes to button (``/Btn``) or signature (``/Sig``) fields are rejected;
* adding or modifying actions (``/AA``, ``/A``) on fields, their widgets or
  the AcroForm dictionary is rejected;
* widget annotations must remain registered on the same page;
* allowing a field to change does **not** amount to allowing arbitrary
  changes to objects it points to: if an object that changed after signing
  (e.g. a shared appearance stream or a shared appearance resource such as
  a font) is reachable from the value/appearance subgraph of several fields,
  *all* affected fields must be permitted by the permission policy.
  Permissions are never inferred from the first reference encountered.

Revisions are vetted one at a time, always comparing the actual signed
revision against each intermediate revision and the final revision, so
changes that were made and later undone (or objects that were redefined
across revisions) are still analysed against the real object graphs
involved. Anything that cannot be accounted for precisely is rejected
rather than silently downgraded.
"""

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from pyhanko.pdf_utils import generic, misc
from pyhanko.pdf_utils.reader import (
    HistoricalResolver,
    PdfFileReader,
    RawPdfPath,
)
from pyhanko.sign.fields import FieldMDPSpec, MDPPerm

from .constants import VALUE_UPDATE_KEYS
from .policies import DEFAULT_DIFF_POLICY, _is_id
from .policy_api import (
    DiffPolicy,
    DiffResult,
    ModificationLevel,
    SuspiciousModification,
)

logger = logging.getLogger(__name__)

__all__ = [
    'FieldChangeNotPermitted',
    'FieldChangePermissionPolicy',
    'FieldChangeRequest',
    'FieldChangeRestrictedDiffPolicy',
    'WhitelistFieldChangePolicy',
]


class FieldChangeNotPermitted(SuspiciousModification):
    """
    Error indicating that a form field change was rejected by the
    configured :class:`FieldChangePermissionPolicy` or by the structural
    checks of :class:`FieldChangeRestrictedDiffPolicy`.

    The offending field and/or object are recorded on the exception
    for diagnostic purposes.
    """

    def __init__(
        self,
        message: str,
        *,
        field_name: str | None = None,
        reference: generic.Reference | None = None,
    ):
        super().__init__(message)
        self.field_name = field_name
        """
        Fully qualified name of the field involved, if applicable.
        """
        self.reference = reference
        """
        Reference to the PDF object involved, if applicable.
        """


@dataclass(frozen=True)
class FieldChangeRequest:
    """
    Description of a field change that a :class:`FieldChangePermissionPolicy`
    is asked to adjudicate.
    """

    signature: Any
    """
    The signature being validated, as bound by the caller on the
    :class:`FieldChangeRestrictedDiffPolicy` (``None`` if not bound).
    Typically an instance of
    :class:`~pyhanko.sign.validation.pdf_embedded.EmbeddedPdfSignature`.
    """

    signed_revision: int
    """
    The revision in which the signature being validated was created.
    """

    revision: int
    """
    The revision currently being vetted.
    """

    fq_field_name: str
    """
    The fully qualified name of the field that was changed.
    """


class FieldChangePermissionPolicy:
    """
    Callback interface adjudicating post-signing changes to individual
    form fields. Implementations must raise :class:`FieldChangeNotPermitted`
    (or another :class:`~pyhanko.sign.diff_analysis.SuspiciousModification`)
    to reject a change, and return ``None`` to accept it.
    """

    def check_field_change(self, request: FieldChangeRequest) -> None:
        """
        :param request:
            The :class:`FieldChangeRequest` to adjudicate.
        :raise FieldChangeNotPermitted:
            if the change is not permitted.
        """
        raise NotImplementedError


class WhitelistFieldChangePolicy(FieldChangePermissionPolicy):
    """
    Permission policy that allows changes to an explicitly enumerated set
    of fully qualified field names, and rejects all others.

    :param permitted_fields:
        The complete set of fully qualified names of fields that may be
        modified after signing.
    """

    def __init__(self, permitted_fields: Iterable[str]):
        self.permitted_fields = frozenset(permitted_fields)

    def check_field_change(self, request: FieldChangeRequest) -> None:
        if request.fq_field_name not in self.permitted_fields:
            raise FieldChangeNotPermitted(
                f"Field {request.fq_field_name!r} was modified in revision "
                f"{request.revision}, but it is not in the set of fields "
                f"that may be modified after signing.",
                field_name=request.fq_field_name,
            )


@dataclass(frozen=True)
class _FieldTreeEntry:
    """
    Bookkeeping record for one named field in one revision.
    """

    fq_name: str
    field_ref: generic.Reference
    field_type: str | None
    canonical_path: RawPdfPath
    widget_refs: set


def _list_field_tree(
    resolver: HistoricalResolver, exc_cls=misc.PdfReadError
) -> dict[str, _FieldTreeEntry]:
    """
    Strictly list the field tree of one revision, recording for every named
    field its object reference, position in the tree and widget annotations.

    Any structural anomaly results in an exception: unanalysable field trees
    are never treated as harmless.
    """

    entries: dict[str, _FieldTreeEntry] = {}
    try:
        acroform = resolver.root['/AcroForm']
    except KeyError:
        return entries
    if not isinstance(acroform, generic.DictionaryObject):
        raise exc_cls("/AcroForm is not a dictionary")
    try:
        top_fields = acroform['/Fields']
    except KeyError:
        return entries

    def _walk(
        arr, parent_name, path, inherited_ft, widget_collector, refs_in_path
    ):
        if not isinstance(arr, generic.ArrayObject):
            raise exc_cls("Field list is not an array.")
        names_seen = set()
        for ix, item in enumerate(arr):
            if not isinstance(item, generic.IndirectObject):
                raise exc_cls("Fields must be indirect objects.")
            ref = item.reference
            if ref in refs_in_path:
                raise exc_cls("Circular reference in field tree.")
            field = resolver(ref)
            if not isinstance(field, generic.DictionaryObject):
                raise exc_cls("Fields must be dictionary objects.")
            try:
                name = field.raw_get('/T')
            except KeyError:
                # a nameless entry in a /Kids array is a widget annotation
                # belonging to the field whose /Kids array we're walking
                if widget_collector is None:
                    raise exc_cls(
                        "Top-level entry in /Fields without a partial name."
                    )
                widget_collector.add(ref)
                continue
            if not isinstance(
                name, (generic.TextStringObject, generic.ByteStringObject)
            ):
                raise exc_cls("Field names must be strings.")
            if name in names_seen:
                raise exc_cls(f"Duplicate field name {name!r}.")
            if '.' in name:
                raise exc_cls("Partial names must not contain periods.")
            names_seen.add(name)

            fq_name = parent_name + "." + name if parent_name else name
            if fq_name in entries:
                raise exc_cls(f"Duplicate field name {fq_name!r}.")
            field_type = field.raw_get('/FT') if '/FT' in field else None
            if field_type is None:
                field_type = inherited_ft
            field_path = path + ix
            kids = field.get('/Kids', None)
            widget_refs: set = set()
            entries[fq_name] = _FieldTreeEntry(
                fq_name=fq_name,
                field_ref=ref,
                field_type=field_type,
                canonical_path=field_path,
                widget_refs=widget_refs,
            )
            if kids is not None:
                _walk(
                    kids,
                    fq_name,
                    field_path + '/Kids',
                    field_type,
                    widget_refs,
                    refs_in_path | {ref},
                )

    _walk(
        top_fields,
        "",
        RawPdfPath('/Root', '/AcroForm', '/Fields'),
        None,
        None,
        frozenset(),
    )
    return entries


def _annot_page_map(
    resolver: HistoricalResolver, exc_cls
) -> dict[generic.Reference, object]:
    """
    Map every widget/annotation reference in the page tree to the page
    that references it (page reference if available, else the page's path).
    """

    try:
        pages_root = resolver.root.raw_get('/Pages')
    except KeyError:
        raise exc_cls("No /Pages entry in document catalog.")
    root_ref = (
        pages_root.reference
        if isinstance(pages_root, generic.IndirectObject)
        else None
    )
    result: dict[generic.Reference, object] = {}

    def _walk(node, node_ref, path, seen):
        if not isinstance(node, generic.DictionaryObject):
            raise exc_cls("Page tree node is not a dictionary.")
        if node_ref is not None:
            if node_ref in seen:
                raise exc_cls("Circular reference in page tree.")
            seen = seen | {node_ref}
        node_type = node.get('/Type', None)
        if node_type == '/Pages':
            try:
                kids = node['/Kids']
            except KeyError:
                raise exc_cls("No /Kids in /Pages node.")
            for ix, kid in enumerate(kids):
                if not isinstance(kid, generic.IndirectObject):
                    raise exc_cls("Page tree nodes must be indirect objects.")
                _walk(
                    resolver(kid.reference),
                    kid.reference,
                    path + '/Kids' + ix,
                    seen,
                )
        elif node_type == '/Page':
            try:
                annots = node['/Annots']
            except KeyError:
                return
            if not isinstance(annots, generic.ArrayObject):
                raise exc_cls("/Annots is not an array.")
            anchor = node_ref if node_ref is not None else path
            for annot in annots:
                if isinstance(annot, generic.IndirectObject):
                    result[annot.reference] = anchor
        else:
            raise exc_cls("Invalid page tree node.")

    _walk(
        resolver(root_ref) if root_ref is not None else pages_root,
        root_ref,
        RawPdfPath('/Root', '/Pages'),
        frozenset(),
    )
    return result


def _raw_get_or_null(dictionary: generic.DictionaryObject, key: str):
    try:
        return dictionary.raw_get(key)
    except KeyError:
        return generic.NullObject()


def _surface_refs(
    resolver: HistoricalResolver, entry: _FieldTreeEntry
) -> set[generic.Reference]:
    """
    Collect all indirect references reachable from a field's value and
    appearance entries (``/V`` and ``/AP`` of the field and the ``/AP``
    entries of its widget annotations), recursively.

    This is the set of objects whose post-signing modification can affect
    the way the field renders; shared objects (e.g. an appearance stream or
    a font used by several fields) show up in the surface of every field
    that uses them.
    """

    refs: set[generic.Reference] = set()
    xrefs = resolver.reader.xrefs

    def _absorb(obj):
        if isinstance(obj, generic.IndirectObject):
            ref = obj.reference
            if ref in refs:
                return
            try:
                xrefs.get_introducing_revision(ref)
            except KeyError:
                # reference to an undefined object: resolves to null,
                # nothing to absorb
                return
            refs.add(ref)
            obj = resolver(ref)
        if isinstance(obj, generic.DictionaryObject):
            for v in obj.values():
                _absorb(v)
        elif isinstance(obj, generic.ArrayObject):
            for v in obj:
                _absorb(v)

    field = resolver(entry.field_ref)
    # For signature fields, do not absorb /V: the signature dictionary
    # typically references the document catalog (via /Data in its signature
    # reference dictionaries), which would pull the entire document into
    # the surface. Signature value integrity is enforced by the wrapped
    # policy's rules; a signature field's render surface is its /AP.
    value_keys = ('/V', '/AP') if entry.field_type != '/Sig' else ('/AP',)
    for key in value_keys:
        try:
            _absorb(field.raw_get(key))
        except KeyError:
            pass
    for widget_ref in entry.widget_refs:
        widget = resolver(widget_ref)
        try:
            _absorb(widget.raw_get('/AP'))
        except KeyError:
            pass
    return refs


class FieldChangeRestrictedDiffPolicy(DiffPolicy):
    """
    Difference policy that intersects a wrapped
    :class:`~pyhanko.sign.diff_analysis.DiffPolicy` with a caller-supplied
    :class:`FieldChangePermissionPolicy`.

    The wrapped policy (by default
    :const:`~pyhanko.sign.diff_analysis.DEFAULT_DIFF_POLICY`) is always
    consulted first and its restrictions --- including DocMDP and FieldMDP
    enforcement --- remain fully in force; the permission policy can only
    narrow the set of acceptable changes, never widen it.

    See the module documentation for the exact rules enforced.

    :param permission_policy:
        The :class:`FieldChangePermissionPolicy` adjudicating changes to
        individual fields.
    :param base_policy:
        The diff policy to wrap. Defaults to
        :const:`~pyhanko.sign.diff_analysis.DEFAULT_DIFF_POLICY`.
    :param signature:
        The signature being validated (optional). This object is passed
        through to the permission policy in every
        :class:`FieldChangeRequest`; typically an
        :class:`~pyhanko.sign.validation.pdf_embedded.EmbeddedPdfSignature`.
    """

    def __init__(
        self,
        permission_policy: FieldChangePermissionPolicy,
        base_policy: DiffPolicy | None = None,
        signature=None,
    ):
        self.permission_policy = permission_policy
        self.base_policy = (
            base_policy if base_policy is not None else DEFAULT_DIFF_POLICY
        )
        self.signature = signature

    # -- internal helpers ------------------------------------------------

    def _request(
        self, old: HistoricalResolver, new: HistoricalResolver, fq_name: str
    ) -> FieldChangeRequest:
        return FieldChangeRequest(
            signature=self.signature,
            signed_revision=old.revision,
            revision=new.revision,
            fq_field_name=fq_name,
        )

    def _is_permitted(
        self,
        old: HistoricalResolver,
        new: HistoricalResolver,
        fq_name: str,
        cache: dict[str, bool],
    ) -> bool:
        try:
            return cache[fq_name]
        except KeyError:
            pass
        try:
            self.permission_policy.check_field_change(
                self._request(old, new, fq_name)
            )
            permitted = True
        except SuspiciousModification:
            permitted = False
        cache[fq_name] = permitted
        return permitted

    @staticmethod
    def _check_tree_structure(
        old_entries: dict[str, _FieldTreeEntry],
        new_entries: dict[str, _FieldTreeEntry],
    ):
        old_names = set(old_entries)
        new_names = set(new_entries)
        if old_names != new_names:
            added = new_names - old_names
            removed = old_names - new_names
            raise FieldChangeNotPermitted(
                "The field tree was structurally modified after signing: "
                f"fields added or renamed to {sorted(added) or '<none>'}, "
                f"fields removed or renamed from "
                f"{sorted(removed) or '<none>'}.",
                field_name=min(added | removed),
            )
        for fq_name in sorted(old_names):
            old_entry = old_entries[fq_name]
            new_entry = new_entries[fq_name]
            if old_entry.field_ref != new_entry.field_ref:
                raise FieldChangeNotPermitted(
                    f"Field {fq_name!r} was replaced by a different object "
                    f"({old_entry.field_ref!r} -> {new_entry.field_ref!r}).",
                    field_name=fq_name,
                    reference=new_entry.field_ref,
                )
            if old_entry.canonical_path != new_entry.canonical_path:
                raise FieldChangeNotPermitted(
                    f"Field {fq_name!r} was moved within the field tree "
                    f"(reparented or reordered).",
                    field_name=fq_name,
                    reference=new_entry.field_ref,
                )
            if old_entry.field_type != new_entry.field_type:
                raise FieldChangeNotPermitted(
                    f"Field type of {fq_name!r} changed from "
                    f"{old_entry.field_type} to {new_entry.field_type}.",
                    field_name=fq_name,
                    reference=new_entry.field_ref,
                )
            if old_entry.widget_refs != new_entry.widget_refs:
                raise FieldChangeNotPermitted(
                    f"Widget annotations of field {fq_name!r} were added, "
                    "removed or replaced.",
                    field_name=fq_name,
                    reference=new_entry.field_ref,
                )

    @staticmethod
    def _check_widget_ownership(
        old: HistoricalResolver,
        new: HistoricalResolver,
        entries: dict[str, _FieldTreeEntry],
    ):
        old_map = _annot_page_map(old, misc.PdfReadError)
        new_map = _annot_page_map(new, SuspiciousModification)
        for fq_name, entry in entries.items():
            candidates = set(entry.widget_refs)
            candidates.add(entry.field_ref)
            for ref in candidates:
                old_page = old_map.get(ref)
                new_page = new_map.get(ref)
                if old_page != new_page:
                    raise FieldChangeNotPermitted(
                        f"Widget annotation {ref!r} of field {fq_name!r} "
                        "was moved to a different page or detached from "
                        "its page.",
                        field_name=fq_name,
                        reference=ref,
                    )

    @staticmethod
    def _check_actions_and_widgets(
        old: HistoricalResolver,
        new: HistoricalResolver,
        entries: dict[str, _FieldTreeEntry],
    ):
        """
        Reject action (``/AA``, ``/A``) changes on the AcroForm dictionary
        and on field dictionaries, and any modification whatsoever to
        widget annotation dictionaries, with field-specific error messages.
        """
        try:
            old_acroform = old.root['/AcroForm']
            new_acroform = new.root['/AcroForm']
        except KeyError:
            old_acroform = new_acroform = None
        if isinstance(old_acroform, generic.DictionaryObject) and isinstance(
            new_acroform, generic.DictionaryObject
        ):
            for key in ('/AA', '/A'):
                if not _is_id(
                    _raw_get_or_null(old_acroform, key),
                    _raw_get_or_null(new_acroform, key),
                ):
                    raise FieldChangeNotPermitted(
                        f"Action entry {key} on the AcroForm dictionary was "
                        "added, modified or deleted after signing."
                    )
        for fq_name, entry in entries.items():
            old_field = old(entry.field_ref)
            new_field = new(entry.field_ref)
            for key in ('/AA', '/A'):
                if not _is_id(
                    _raw_get_or_null(old_field, key),
                    _raw_get_or_null(new_field, key),
                ):
                    raise FieldChangeNotPermitted(
                        f"Action entry {key} of field {fq_name!r} was added, "
                        "modified or deleted after signing.",
                        field_name=fq_name,
                        reference=entry.field_ref,
                    )
            for widget_ref in entry.widget_refs:
                if not _is_id(old(widget_ref), new(widget_ref)):
                    raise FieldChangeNotPermitted(
                        f"Widget annotation {widget_ref!r} of field "
                        f"{fq_name!r} was modified after signing.",
                        field_name=fq_name,
                        reference=widget_ref,
                    )

    def _check_field_content(
        self,
        old: HistoricalResolver,
        new: HistoricalResolver,
        entries: dict[str, _FieldTreeEntry],
        fq_name: str,
    ):
        """
        Verify that the (permitted) field's dictionary only differs in
        value/appearance-related keys, and never in action keys.
        """
        entry = entries[fq_name]
        old_field = old(entry.field_ref)
        new_field = new(entry.field_ref)
        all_keys = set(old_field.keys()) | set(new_field.keys())
        for key in sorted(all_keys - VALUE_UPDATE_KEYS - {'/AA', '/A'}):
            if not _is_id(
                _raw_get_or_null(old_field, key),
                _raw_get_or_null(new_field, key),
            ):
                raise FieldChangeNotPermitted(
                    f"Entry {key} of field {fq_name!r} was modified after "
                    "signing; only value (/V) and appearance-related "
                    "updates are allowed.",
                    field_name=fq_name,
                    reference=entry.field_ref,
                )

    def _check_shared_surfaces(
        self,
        old: HistoricalResolver,
        new: HistoricalResolver,
        entries: dict[str, _FieldTreeEntry],
        permitted_cache: dict[str, bool],
    ):
        """
        For every object that changed after signing and belongs to the
        value/appearance surface of some field, verify that *all* fields
        whose surface contains the object are permitted to change.
        """
        xrefs = old.reader.xrefs
        signed_rev = old.revision
        surfaces = {
            fq_name: _surface_refs(new, entry)
            for fq_name, entry in entries.items()
        }
        for fq_name, surface in surfaces.items():
            for ref in surface:
                try:
                    introducing = xrefs.get_introducing_revision(ref)
                    last_change = xrefs.get_last_change(ref)
                except KeyError:
                    # undefined object; resolves to null
                    continue
                if last_change <= signed_rev:
                    continue
                if introducing <= signed_rev and _is_id(old(ref), new(ref)):
                    # pre-existing object that was overridden with an
                    # identical copy: a no-op, not a change
                    continue
                # the object changed after signing; gather all affected
                # fields instead of attributing it to the first field
                affected = [
                    other
                    for other, other_surface in surfaces.items()
                    if ref in other_surface
                ]
                for other in affected:
                    if self._is_permitted(old, new, other, permitted_cache):
                        continue
                    if other == fq_name and len(affected) == 1:
                        msg = (
                            f"Object {ref!r}, which changed after signing, "
                            f"belongs to the value/appearance data of field "
                            f"{other!r}, but changes to {other!r} are not "
                            "permitted."
                        )
                    else:
                        msg = (
                            f"Object {ref!r}, which changed after signing, "
                            f"is shared between the value/appearance data "
                            f"of field {fq_name!r} and field {other!r}, "
                            f"but changes to {other!r} are not permitted."
                        )
                    raise FieldChangeNotPermitted(
                        msg, field_name=other, reference=ref
                    )

    # -- DiffPolicy API --------------------------------------------------

    def apply(
        self,
        old: HistoricalResolver,
        new: HistoricalResolver,
        field_mdp_spec: FieldMDPSpec | None = None,
        doc_mdp: MDPPerm | None = None,
    ) -> DiffResult:
        # Structural vetting first: this yields precise, field-level error
        # messages for tree manipulations. Anything that cannot be analysed
        # raises, and is therefore never treated as harmless.
        old_entries = _list_field_tree(old, misc.PdfReadError)
        new_entries = _list_field_tree(new, SuspiciousModification)
        self._check_tree_structure(old_entries, new_entries)
        self._check_widget_ownership(old, new, old_entries)
        self._check_actions_and_widgets(old, new, old_entries)

        # The wrapped policy runs in full; its verdict (including DocMDP /
        # FieldMDP enforcement) is intersected with ours, never overridden.
        base_result = self.base_policy.apply(
            old, new, field_mdp_spec=field_mdp_spec, doc_mdp=doc_mdp
        )

        permitted_cache: dict[str, bool] = {}

        # Fields whose field dictionary differs between the revisions.
        # (The wrapped policy's changed_form_fields also covers fields whose
        # appearance streams were updated in place; take the union.)
        differing = set()
        for fq_name, entry in old_entries.items():
            if not _is_id(old(entry.field_ref), new(entry.field_ref)):
                differing.add(fq_name)
        to_check = differing | base_result.changed_form_fields

        for fq_name in sorted(to_check):
            try:
                entry = old_entries[fq_name]
            except KeyError:
                raise SuspiciousModification(
                    f"Changed field {fq_name!r} reported by the wrapped "
                    "policy could not be located in the signed revision's "
                    "field tree; refusing to guess."
                )
            self.permission_policy.check_field_change(
                self._request(old, new, fq_name)
            )
            permitted_cache[fq_name] = True
            if entry.field_type != '/Tx':
                raise FieldChangeNotPermitted(
                    f"Field {fq_name!r} is of type {entry.field_type}; only "
                    "changes to pre-existing text (/Tx) fields can be "
                    "permitted by a field change permission policy.",
                    field_name=fq_name,
                    reference=entry.field_ref,
                )
            self._check_field_content(old, new, old_entries, fq_name)

        # Unchanged, non-permitted fields must be completely untouched:
        # any field dictionary that differs but was not cleared above is
        # rejected. (Fields in `differing` that are not permitted already
        # raised in the loop above via the permission policy.)
        self._check_shared_surfaces(old, new, old_entries, permitted_cache)

        return base_result

    def review_file(
        self,
        reader: PdfFileReader,
        base_revision: int | HistoricalResolver,
        field_mdp_spec: FieldMDPSpec | None = None,
        doc_mdp: MDPPerm | None = None,
    ) -> DiffResult | SuspiciousModification:
        """
        Review every intermediate revision between the signed revision and
        the current one individually, always diffing the actual signed
        revision against the revision under scrutiny (never two adjacent
        revisions), so that changes that were later undone and objects that
        were redefined across revisions are still analysed against the real
        object graphs involved.
        """
        if isinstance(base_revision, int):
            base_rev_resolver = reader.get_historical_resolver(base_revision)
            base_revision_no = base_revision
        else:
            base_rev_resolver = base_revision
            base_revision_no = base_rev_resolver.revision

        rev_count = reader.xrefs.total_revisions
        current_max = ModificationLevel.NONE
        changed_form_fields: set[str] = set()
        for revision in range(base_revision_no + 1, rev_count):
            try:
                diff_result = self.apply(
                    old=base_rev_resolver,
                    new=reader.get_historical_resolver(revision),
                    field_mdp_spec=field_mdp_spec,
                    doc_mdp=doc_mdp,
                )
            except SuspiciousModification as e:
                logger.warning(
                    'Error in diff operation between revision '
                    f'{base_revision_no} and {revision}',
                    exc_info=e,
                )
                return e
            current_max = max(current_max, diff_result.modification_level)
            changed_form_fields |= diff_result.changed_form_fields
        return DiffResult(current_max, changed_form_fields)
