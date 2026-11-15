.. _diff-analysis:

Incremental update analysis
===========================

.. versionchanged:: 0.2.0

    The initial ad-hoc approach was replaced by a more extensible and
    maintainable rule-based validation system. See
    :mod:`pyhanko.sign.diff_analysis`.

.. testsetup:: *

    globals().update(make_doc_env(DocEnvSpec(
        files={},
        signers=(),
        signed_documents=(
            SignedDocSpec(profile=SignatureProfile.PADES_LTA),
        ),
        trust=TrustSpec(fetch_revocation=True),
    )))

.. testcleanup:: *

    teardown_doc_env(_doc_env)


.. |PdfSignatureStatus| replace:: :class:`~.pyhanko.sign.validation.status.PdfSignatureStatus`

As explained in :ref:`the CLI documentation <validation-general-incremental-updates>`,
the PDF standard has provisions that allow files to be updated by appending
so-called "incremental updates". This also works for signed documents, since
appending data does not destroy the cryptographic integrity of the signed data.

However, since incremental updates can change essentially any aspect of
the resulting document, validators need to be careful to evaluate whether
these updates were added for a legitimate reason.
Examples of such legitimate reasons could include the following:

* adding a second signature,
* adding comments,
* filling in (part of) a form,
* updating document metadata,
* performing cryptographic "bookkeeping work" such as appending fresh document
  timestamps and/or revocation information to ensure the long-term verifiability
  of a signature.

Not all of these reasons are necessarily always valid: the signer can tell
the validator which modifications they allow to go ahead without invalidating
their signature. This can either be done through the "DocMDP" setting (see
:class:`~.pyhanko.sign.fields.MDPPerm`), or for form fields, more granularly
using FieldMDP settings (see :class:`~.pyhanko.sign.fields.FieldMDPSpec`).

That being said, the standard does not specify a concrete procedure for
validating any of this. PyHanko takes a reject-by-default approach: the
difference analysis tool uses rules to compare document revisions, and judge
which object updating operations are legitimate (at a given
:class:`~.pyhanko.sign.fields.MDPPerm` level). Any modifications for which
there is no justification invalidate the signature.

The default diff policy is defined in
:const:`~pyhanko.sign.diff_analysis.DEFAULT_DIFF_POLICY`, but you can define
your own, either by implementing your own subclass of
:class:`~.pyhanko.sign.diff_analysis.DiffPolicy`, or by defining your own rules
and passing those to an instance of :class:`~.pyhanko.sign.diff_analysis.StandardDiffPolicy`.
:class:`~.pyhanko.sign.diff_analysis.StandardDiffPolicy` takes care of some
boilerplate for you, and is the mechanism backing
:const:`~pyhanko.sign.diff_analysis.DEFAULT_DIFF_POLICY`.
Explaining precisely how to implement custom diff rules is beyond the scope
of this guide, but you can take a look at the source of
the :mod:`~pyhanko.sign.diff_analysis` module for more information.

To actually use a diff policy, pass it to
:func:`~.pyhanko.sign.validation.validate_pdf_signature` via the
``diff_policy`` parameter.

.. testcode::

    from pyhanko.keys import load_cert_from_pemder
    from pyhanko_certvalidator import ValidationContext
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko.sign.diff_analysis import DEFAULT_DIFF_POLICY

    root_cert = load_cert_from_pemder('path/to/certfile')
    vc = ValidationContext(trust_roots=[root_cert])

    # Substitute your own DiffPolicy instance here; the default is used
    # for illustration.
    diff_policy = DEFAULT_DIFF_POLICY

    with open('document.pdf', 'rb') as doc:
        r = PdfFileReader(doc)
        sig = r.embedded_signatures[0]
        status = validate_pdf_signature(sig, vc, diff_policy=diff_policy)
        print(status.pretty_print_details())

.. testoutput::
    :hide:

    ...
    The signature is judged VALID.


The :attr:`~.pyhanko.sign.validation.status.PdfSignatureStatus.modification_level`
and :attr:`~.pyhanko.sign.validation.status.PdfSignatureStatus.docmdp_ok` attributes
on |PdfSignatureStatus| will tell you to what degree the signed file has been
modified after signing (according to the diff policy used).


.. warning::
    The most lenient MDP level,
    :attr:`~.pyhanko.sign.fields.MDPPerm.ANNOTATE`, is currently not
    supported by the default diff policy.

.. danger::
    Due to the lack of standardisation when it comes to signature validation,
    correctly adjudicating incremental updates is inherently somewhat risky
    and ill-defined, so until pyHanko matures, you probably shouldn't rely
    on its judgments too heavily.

    Should you run into unexpected results, by all means
    `start a discussion <https://github.com/MatthiasValvekens/pyHanko/discussions>`_.
    All information helps!


.. _diff-analysis-field-change-policy:

Restricting which fields may be filled in after signing
-------------------------------------------------------

The default diff policy intentionally interprets DocMDP's "form fill"
permission rather liberally: any form field may be filled in, and new
signature fields may appear. If your application needs to be stricter ---
for example, because a signed form may only be countersigned by filling in
a few explicitly enumerated text fields --- you can inject a
:class:`~pyhanko.sign.diff_analysis.field_change_policy.FieldChangePermissionPolicy`
into the validation process by wrapping the regular diff policy in a
:class:`~pyhanko.sign.diff_analysis.field_change_policy.FieldChangeRestrictedDiffPolicy`.

This wrapper *intersects* the wrapped policy's verdict with yours: it can
only ever reject changes that the wrapped policy would have accepted, never
the other way around. In particular, DocMDP and FieldMDP restrictions
imposed by the document's signatures remain fully in force.
On top of that, it enforces the following rules:

* only changes to the value (``/V``) and normal appearance data of
  **text fields that already existed at signing time** can be permitted;
* any structural change to the field tree is rejected (renames, duplicate
  names, reparenting, new or deleted fields, replacement of field objects);
* changes to button or signature fields are rejected;
* adding or modifying actions (``/AA``, ``/A``) is rejected;
* widget annotations must remain on their original page;
* permission is adjudicated per affected field, not per object: if an
  object that changed after signing (e.g. a shared appearance stream or
  a shared font) is used by several fields, *all* of them must be
  permitted --- permissions are never inferred from the first reference
  encountered.

Revisions are vetted one at a time against the actual signed revision, so
changes that were later undone (or objects that were redefined across
revisions) are still analysed. Changes that cannot be accounted for
precisely are rejected with a
:class:`~pyhanko.sign.diff_analysis.field_change_policy.FieldChangeNotPermitted`
error naming the field and object involved; they are never silently
treated as harmless.

The most common case --- "only these fully qualified field names may
change" --- is covered by
:class:`~pyhanko.sign.diff_analysis.field_change_policy.WhitelistFieldChangePolicy`:

.. code-block:: python

    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.diff_analysis import (
        FieldChangeRestrictedDiffPolicy,
        WhitelistFieldChangePolicy,
    )
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext

    vc = ValidationContext(trust_roots=[...])

    with open('signed-form.pdf', 'rb') as doc:
        r = PdfFileReader(doc)
        sig = r.embedded_signatures[0]
        diff_policy = FieldChangeRestrictedDiffPolicy(
            WhitelistFieldChangePolicy({'Text1', 'Text2'}),
            # optional: forwarded to the permission policy in every
            # FieldChangeRequest, together with the revision numbers
            signature=sig,
        )
        status = validate_pdf_signature(sig, vc, diff_policy=diff_policy)
        print(status.pretty_print_details())

If you need more context to make the decision, implement
:meth:`~pyhanko.sign.diff_analysis.field_change_policy.FieldChangePermissionPolicy.check_field_change`
yourself. It is called once for every field that was changed in a revision,
with a
:class:`~pyhanko.sign.diff_analysis.field_change_policy.FieldChangeRequest`
that carries the signature being validated, the signed revision, the
revision being vetted and the fully qualified field name. Raise
:class:`~pyhanko.sign.diff_analysis.field_change_policy.FieldChangeNotPermitted`
to reject the change.

.. code-block:: python

    from pyhanko.sign.diff_analysis import (
        FieldChangeNotPermitted,
        FieldChangePermissionPolicy,
    )


    class MyPolicy(FieldChangePermissionPolicy):
        def check_field_change(self, request):
            # request.signature, request.signed_revision,
            # request.revision, request.fq_field_name
            if not self.is_allowed(request):
                raise FieldChangeNotPermitted(
                    f"Change to {request.fq_field_name!r} denied",
                    field_name=request.fq_field_name,
                )


If necessary, you can opt to turn off difference analysis altogether.
This is sometimes a very reasonable thing to do, e.g. in the following cases:

* you don't trust pyHanko to correctly evaluate the changes;
* the (sometimes rather large) performance cost of doing the diff analysis
  is not worth the benefits;
* you need validate only one signature, after which the document shouldn't
  change at all.

In these cases, you might want to rely on the
:attr:`~.pyhanko.sign.validation.ModificationInfo.coverage` property
of |PdfSignatureStatus| instead. This property describes the degree to which
a given signature covers a file, and is much cheaper/easier to compute.

Anyhow, to disable diff analysis completely, it suffices to pass the
``skip_diff`` parameter to
:func:`~.pyhanko.sign.validation.validate_pdf_signature`.


.. testcode::

    from pyhanko.keys import load_cert_from_pemder
    from pyhanko_certvalidator import ValidationContext
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature

    root_cert = load_cert_from_pemder('path/to/certfile')
    vc = ValidationContext(trust_roots=[root_cert])

    with open('document.pdf', 'rb') as doc:
        r = PdfFileReader(doc)
        sig = r.embedded_signatures[0]
        status = validate_pdf_signature(sig, vc, skip_diff=True)
        print(status.pretty_print_details())

.. testoutput::
    :hide:

    ...
    The signature is judged VALID.
