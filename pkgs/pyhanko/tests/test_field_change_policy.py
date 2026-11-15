"""
Tests for the injectable field-change permission policy
(:mod:`pyhanko.sign.diff_analysis.field_change_policy`).

Everything in this module is self-contained: the CA is generated on the fly,
the forms are produced with pyHanko itself, and validation runs fully
offline (no OCSP/CRL fetching, no PDF viewer, no script execution).
"""

from datetime import UTC, datetime
from io import BytesIO

import pytest
from asn1crypto import keys as asn1_keys
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.content import RawContent
from pyhanko.pdf_utils.generic import pdf_name, pdf_string
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.layout import BoxConstraints
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PdfFileWriter
from pyhanko.sign import fields, signers
from pyhanko.sign.diff_analysis import (
    DEFAULT_DIFF_POLICY,
    FieldChangeNotPermitted,
    FieldChangePermissionPolicy,
    FieldChangeRestrictedDiffPolicy,
    ModificationLevel,
    SuspiciousModification,
    WhitelistFieldChangePolicy,
)
from pyhanko.sign.fields import FieldMDPAction, FieldMDPSpec, MDPPerm
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore
from pyhanko_testing_commons.test_data.samples import simple_page

# --- throwaway CA, generated at test time ---------------------------------


def _generate_temp_ca():
    not_before = datetime(2020, 1, 1, tzinfo=UTC)
    not_after = datetime(2040, 1, 1, tzinfo=UTC)

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, 'Temporary Test Root CA')]
    )
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    signer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, 'Temporary Test Signer')]
    )
    signer_cert = (
        x509.CertificateBuilder()
        .subject_name(signer_name)
        .issuer_name(root_name)
        .public_key(signer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                root_key.public_key()
            ),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    der = serialization.Encoding.DER
    root_asn1 = asn1_x509.Certificate.load(root_cert.public_bytes(der))
    signer_cert_asn1 = asn1_x509.Certificate.load(signer_cert.public_bytes(der))
    signer_key_asn1 = asn1_keys.PrivateKeyInfo.load(
        signer_key.private_bytes(
            der, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    signer = signers.SimpleSigner(
        signing_cert=signer_cert_asn1,
        signing_key=signer_key_asn1,
        cert_registry=SimpleCertificateStore.from_certs(
            [root_asn1, signer_cert_asn1]
        ),
    )
    vc = ValidationContext(trust_roots=[root_asn1])
    return signer, vc


@pytest.fixture(scope='module')
def temp_ca():
    return _generate_temp_ca()


@pytest.fixture(scope='module')
def temp_signer(temp_ca):
    signer, _ = temp_ca
    return signer


@pytest.fixture(scope='module')
def temp_vc(temp_ca):
    _, vc = temp_ca
    return vc


# --- form generation helpers ------------------------------------------------

TEXT_FIELD_RECTS = [(10, 100, 130, 120), (10, 70, 130, 90), (10, 40, 130, 60)]


def _appearance_stream(w, text):
    return w.add_object(
        RawContent(
            box=BoxConstraints(height=18, width=120),
            data=b'q 0 0 1 rg BT /Helv 12 Tf 2 6 Td (%s) Tj ET Q'
            % text.encode('ascii'),
        ).as_form_xobject()
    )


def _text_field_dict(name, page_ref, rect, ap_ref=None, value=None):
    tf = generic.DictionaryObject(
        {
            pdf_name('/FT'): pdf_name('/Tx'),
            pdf_name('/T'): pdf_string(name),
            pdf_name('/Type'): pdf_name('/Annot'),
            pdf_name('/Subtype'): pdf_name('/Widget'),
            pdf_name('/Rect'): generic.ArrayObject(
                [generic.NumberObject(x) for x in rect]
            ),
            pdf_name('/F'): generic.NumberObject(4),
            pdf_name('/DA'): pdf_string('/Helv 0 Tf 0 g'),
            pdf_name('/P'): page_ref,
        }
    )
    if value is not None:
        tf[pdf_name('/V')] = pdf_string(value)
    if ap_ref is not None:
        tf[pdf_name('/AP')] = generic.DictionaryObject({pdf_name('/N'): ap_ref})
    return tf


def _build_form_bytes(
    *,
    field_names=('Text1', 'Text2'),
    n_pages=1,
    shared_ap=False,
    sig_field_spec=None,
):
    w = PdfFileWriter()
    page_refs = [
        w.insert_page(simple_page(w, f'Page {i + 1}')) for i in range(n_pages)
    ]
    fields.append_signature_field(
        w,
        sig_field_spec
        or fields.SigFieldSpec(sig_field_name='Sig1', box=(10, 10, 110, 40)),
    )
    acroform = w.root['/AcroForm']
    fields_arr = acroform['/Fields']
    shared_ap_ref = _appearance_stream(w, 'same') if shared_ap else None
    for ix, name in enumerate(field_names):
        tf_ref = w.add_object(
            _text_field_dict(
                name,
                page_refs[0],
                TEXT_FIELD_RECTS[ix % len(TEXT_FIELD_RECTS)],
                ap_ref=shared_ap_ref,
                value='same' if shared_ap else None,
            )
        )
        fields_arr.append(tf_ref)
        w.register_annotation(page_refs[0], tf_ref)
    out = BytesIO()
    w.write(out)
    return out.getvalue()


def _sign_form(temp_signer, **form_kwargs):
    form_bytes = _build_form_bytes(**form_kwargs)
    w = IncrementalPdfFileWriter(BytesIO(form_bytes))
    return signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(field_name='Sig1'),
        signer=temp_signer,
    )


def _find_field_ref(w, name):
    for field_ref in w.root['/AcroForm']['/Fields']:
        field = field_ref.get_object()
        if field.get('/T', None) == name:
            return field_ref
    raise AssertionError(f'No field named {name}')


def _fill_text_field(w, name, value):
    field = _find_field_ref(w, name).get_object()
    field[pdf_name('/V')] = pdf_string(value)
    field[pdf_name('/AP')] = generic.DictionaryObject(
        {pdf_name('/N'): _appearance_stream(w, value)}
    )
    w.update_container(field)


def _increment(out, mutate):
    w = IncrementalPdfFileWriter(out)
    mutate(w)
    new_out = BytesIO()
    w.write(new_out)
    return new_out


def _validate(out, vc, permitted, sig_ix=0):
    r = PdfFileReader(out)
    sig = r.embedded_signatures[sig_ix]
    diff_policy = FieldChangeRestrictedDiffPolicy(
        WhitelistFieldChangePolicy(permitted), signature=sig
    )
    return validate_pdf_signature(sig, vc, diff_policy=diff_policy)


def _assert_crypto_ok(status):
    # cryptographic validity and trust are independent of the
    # document modification policy verdict
    assert status.intact
    assert status.valid
    assert status.trusted


# --- tests -------------------------------------------------------------------


def test_permitted_text_field_fill_accepted(temp_signer, temp_vc):
    out = _sign_form(temp_signer)
    out = _increment(out, lambda w: _fill_text_field(w, 'Text1', 'hello'))

    status = _validate(out, temp_vc, {'Text1'})
    _assert_crypto_ok(status)
    assert status.docmdp_ok
    assert status.modification_level == ModificationLevel.FORM_FILLING
    assert status.bottom_line


def test_all_listed_fields_may_be_filled(temp_signer, temp_vc):
    out = _sign_form(temp_signer)

    def _mutate(w):
        _fill_text_field(w, 'Text1', 'foo')
        _fill_text_field(w, 'Text2', 'bar')

    out = _increment(out, _mutate)
    status = _validate(out, temp_vc, {'Text1', 'Text2'})
    _assert_crypto_ok(status)
    assert status.bottom_line


def test_unlisted_text_field_fill_rejected(temp_signer, temp_vc):
    out = _sign_form(temp_signer)
    out = _increment(out, lambda w: _fill_text_field(w, 'Text2', 'sneaky'))

    status = _validate(out, temp_vc, {'Text1'})
    # the signature itself is cryptographically fine ...
    _assert_crypto_ok(status)
    # ... but the modification policy rejects the change
    assert status.docmdp_ok is False
    assert not status.bottom_line
    assert isinstance(status.diff_result, FieldChangeNotPermitted)
    assert status.diff_result.field_name == 'Text2'
    assert 'Text2' in str(status.diff_result)

    # the default (permissive) policy accepts the same file, proving that
    # the failure comes from the injected policy, not from cryptography
    r = PdfFileReader(out)
    default_status = validate_pdf_signature(
        r.embedded_signatures[0], temp_vc, diff_policy=DEFAULT_DIFF_POLICY
    )
    assert default_status.bottom_line


def test_sig_field_change_rejected(temp_signer, temp_vc):
    # even an explicitly whitelisted /Sig field is rejected when its
    # dictionary is tampered with: only /Tx fields can be covered
    # by a field change permission policy
    out = _sign_form(temp_signer)

    def _mutate(w):
        sig_field = _find_field_ref(w, 'Sig1').get_object()
        sig_field[pdf_name('/Ff')] = generic.NumberObject(1)
        w.update_container(sig_field)

    out = _increment(out, _mutate)
    status = _validate(out, temp_vc, {'Sig1'})
    _assert_crypto_ok(status)
    assert not status.bottom_line
    assert isinstance(status.diff_result, FieldChangeNotPermitted)
    assert status.diff_result.field_name == 'Sig1'
    assert '/Tx' in str(status.diff_result)


def test_new_field_rejected(temp_signer, temp_vc):
    out = _sign_form(temp_signer)

    def _mutate(w):
        page_ref = w.root['/Pages']['/Kids'].raw_get(0)
        tf_ref = w.add_object(
            _text_field_dict('Text3', page_ref, (10, 10, 130, 30))
        )
        fields_arr = w.root['/AcroForm']['/Fields']
        fields_arr.append(tf_ref)
        w.update_container(fields_arr)
        w.register_annotation(page_ref, tf_ref)

    out = _increment(out, _mutate)
    status = _validate(out, temp_vc, {'Text1', 'Text2', 'Text3'})
    _assert_crypto_ok(status)
    assert not status.bottom_line
    assert isinstance(status.diff_result, FieldChangeNotPermitted)
    assert 'structurally modified' in str(status.diff_result)


def test_field_rename_rejected(temp_signer, temp_vc):
    out = _sign_form(temp_signer)

    def _mutate(w):
        tf = _find_field_ref(w, 'Text1').get_object()
        tf[pdf_name('/T')] = pdf_string('Renamed1')
        w.update_container(tf)

    out = _increment(out, _mutate)
    status = _validate(out, temp_vc, {'Text1', 'Text2', 'Renamed1'})
    _assert_crypto_ok(status)
    assert not status.bottom_line
    assert isinstance(status.diff_result, FieldChangeNotPermitted)
    assert 'structurally modified' in str(status.diff_result)


def test_field_reparenting_rejected(temp_signer, temp_vc):
    out = _sign_form(temp_signer)

    def _mutate(w):
        text1_ref = _find_field_ref(w, 'Text1')
        text1 = text1_ref.get_object()
        group = generic.DictionaryObject(
            {
                pdf_name('/T'): pdf_string('Group'),
                pdf_name('/Kids'): generic.ArrayObject([text1_ref]),
            }
        )
        group_ref = w.add_object(group)
        text1[pdf_name('/Parent')] = group_ref
        w.update_container(text1)
        fields_arr = w.root['/AcroForm']['/Fields']
        for ix, fref in enumerate(fields_arr):
            if fref.get_object().get('/T', None) == 'Text1':
                fields_arr[ix] = group_ref
                break
        w.update_container(fields_arr)

    out = _increment(out, _mutate)
    # even if the caller (wrongly) whitelists the new fully qualified name,
    # reparenting must be rejected
    status = _validate(out, temp_vc, {'Text1', 'Text2', 'Group.Text1'})
    _assert_crypto_ok(status)
    assert not status.bottom_line
    assert isinstance(status.diff_result, FieldChangeNotPermitted)
    assert 'structurally modified' in str(status.diff_result)


def test_action_addition_rejected(temp_signer, temp_vc):
    out = _sign_form(temp_signer)

    def _mutate(w):
        tf = _find_field_ref(w, 'Text1').get_object()
        tf[pdf_name('/AA')] = generic.DictionaryObject(
            {
                pdf_name('/K'): generic.DictionaryObject(
                    {
                        pdf_name('/S'): pdf_name('/JavaScript'),
                        pdf_name('/JS'): pdf_string('app.alert("hi")'),
                    }
                )
            }
        )
        w.update_container(tf)

    out = _increment(out, _mutate)
    status = _validate(out, temp_vc, {'Text1'})
    _assert_crypto_ok(status)
    assert not status.bottom_line
    assert isinstance(status.diff_result, FieldChangeNotPermitted)
    assert status.diff_result.field_name == 'Text1'
    assert '/AA' in str(status.diff_result)


def test_widget_page_move_rejected(temp_signer, temp_vc):
    out = _sign_form(temp_signer, n_pages=2)

    def _mutate(w):
        kids = w.root['/Pages']['/Kids']
        page1, page2 = (kid.get_object() for kid in kids)
        text1_ref = _find_field_ref(w, 'Text1')
        annots1 = page1['/Annots']
        annots1.remove(text1_ref)
        w.update_container(page1)
        try:
            annots2 = page2['/Annots']
        except KeyError:
            annots2 = page2[pdf_name('/Annots')] = generic.ArrayObject()
        annots2.append(text1_ref)
        w.update_container(page2)

    out = _increment(out, _mutate)
    status = _validate(out, temp_vc, {'Text1'})
    _assert_crypto_ok(status)
    assert not status.bottom_line
    assert isinstance(status.diff_result, FieldChangeNotPermitted)
    assert status.diff_result.field_name == 'Text1'
    assert 'page' in str(status.diff_result)


def test_shared_appearance_stream_rejected(temp_signer, temp_vc):
    # Text1 and Text2 share one appearance stream; updating it in place
    # after signing affects both fields, so whitelisting only Text1
    # must not be enough
    out = _sign_form(temp_signer, shared_ap=True)

    def _mutate(w):
        text1 = _find_field_ref(w, 'Text1').get_object()
        ap_stream = text1['/AP']['/N'].get_object()
        ap_stream._data = b'q 1 0 0 rg BT /Helv 12 Tf (evil) Tj ET Q'
        ap_stream._encoded_data = None
        w.update_container(ap_stream)

    out = _increment(out, _mutate)

    # sanity check: the default policy considers this a legitimate
    # (in-place) appearance update
    r = PdfFileReader(out)
    default_status = validate_pdf_signature(
        r.embedded_signatures[0], temp_vc, diff_policy=DEFAULT_DIFF_POLICY
    )
    assert default_status.bottom_line

    status = _validate(out, temp_vc, {'Text1'})
    _assert_crypto_ok(status)
    assert not status.bottom_line
    assert isinstance(status.diff_result, FieldChangeNotPermitted)
    assert status.diff_result.field_name == 'Text2'


def test_shared_object_checked_against_all_affected_fields(
    temp_signer, temp_vc
):
    # Unit-level test for the shared-surface check: a base policy that
    # (incorrectly) attributes the shared appearance stream update to the
    # first field referencing it must not cause the change to be accepted
    # when only that first field is whitelisted.
    from pyhanko.sign.diff_analysis import DiffPolicy, DiffResult

    class FirstReferenceAttributionPolicy(DiffPolicy):
        # simulates a (broken) rule that reverse-attributes the shared
        # object to the first field that references it
        def apply(self, old, new, field_mdp_spec=None, doc_mdp=None):
            return DiffResult(ModificationLevel.FORM_FILLING, {'Text1'})

    out = _sign_form(temp_signer, shared_ap=True)

    def _mutate(w):
        text1 = _find_field_ref(w, 'Text1').get_object()
        ap_stream = text1['/AP']['/N'].get_object()
        ap_stream._data = b'q 1 0 0 rg BT /Helv 12 Tf (evil) Tj ET Q'
        ap_stream._encoded_data = None
        w.update_container(ap_stream)

    out = _increment(out, _mutate)

    r = PdfFileReader(out)
    sig = r.embedded_signatures[0]
    policy = FieldChangeRestrictedDiffPolicy(
        WhitelistFieldChangePolicy({'Text1'}),
        base_policy=FirstReferenceAttributionPolicy(),
        signature=sig,
    )
    result = policy.review_file(r, sig.signed_revision)
    assert isinstance(result, FieldChangeNotPermitted)
    assert result.field_name == 'Text2'
    assert result.reference is not None
    assert 'shared' in str(result).lower()

    # whitelisting both affected fields does accept the change
    policy = FieldChangeRestrictedDiffPolicy(
        WhitelistFieldChangePolicy({'Text1', 'Text2'}),
        base_policy=FirstReferenceAttributionPolicy(),
        signature=sig,
    )
    result = policy.review_file(r, sig.signed_revision)
    assert isinstance(result, DiffResult)
    assert result.modification_level == ModificationLevel.FORM_FILLING


def test_intermediate_revision_vetted_even_if_reverted(temp_signer, temp_vc):
    # fill a permitted and a non-permitted field in one revision,
    # then revert the non-permitted field in the next one:
    # the intermediate revision must still be vetted and rejected
    out = _sign_form(temp_signer)

    def _mutate1(w):
        _fill_text_field(w, 'Text1', 'foo')
        _fill_text_field(w, 'Text2', 'bar')

    out = _increment(out, _mutate1)

    def _mutate2(w):
        tf2 = _find_field_ref(w, 'Text2').get_object()
        del tf2[pdf_name('/V')]
        del tf2[pdf_name('/AP')]
        w.update_container(tf2)

    out = _increment(out, _mutate2)

    # the default policy accepts this: the intermediate fill was a
    # legitimate form fill, and the revert restored the signed state
    r = PdfFileReader(out)
    default_status = validate_pdf_signature(
        r.embedded_signatures[0], temp_vc, diff_policy=DEFAULT_DIFF_POLICY
    )
    assert default_status.bottom_line

    status = _validate(out, temp_vc, {'Text1'})
    _assert_crypto_ok(status)
    assert not status.bottom_line
    assert isinstance(status.diff_result, FieldChangeNotPermitted)
    assert status.diff_result.field_name == 'Text2'


def test_docmdp_restriction_not_relaxed(temp_signer, temp_vc):
    # approve with a /Lock dictionary demanding DocMDP "no changes"
    # (but leaving Text1 unlocked): even a whitelisted field fill
    # must remain invalid, because the permission policy can never
    # relax DocMDP
    from pyhanko.sign.diff_analysis import DiffResult

    out = _sign_form(
        temp_signer,
        sig_field_spec=fields.SigFieldSpec(
            sig_field_name='Sig1',
            box=(10, 10, 110, 40),
            field_mdp_spec=FieldMDPSpec(
                FieldMDPAction.EXCLUDE, fields=['Text1']
            ),
            doc_mdp_update_value=MDPPerm.NO_CHANGES,
        ),
    )
    out = _increment(out, lambda w: _fill_text_field(w, 'Text1', 'hello'))

    status = _validate(out, temp_vc, {'Text1'})
    _assert_crypto_ok(status)
    # the diff itself is a legitimate form fill ...
    assert isinstance(status.diff_result, DiffResult)
    assert (
        status.diff_result.modification_level == ModificationLevel.FORM_FILLING
    )
    # ... but it exceeds the DocMDP level demanded by the signature
    assert status.docmdp_ok is False
    assert not status.bottom_line


def test_fieldmdp_lock_not_relaxed(temp_signer, temp_vc):
    # lock Text1 with FieldMDP: the permission policy may not override
    # the lock, even if Text1 is whitelisted
    out = _sign_form(
        temp_signer,
        sig_field_spec=fields.SigFieldSpec(
            sig_field_name='Sig1',
            box=(10, 10, 110, 40),
            field_mdp_spec=FieldMDPSpec(
                FieldMDPAction.INCLUDE, fields=['Text1']
            ),
        ),
    )
    out = _increment(out, lambda w: _fill_text_field(w, 'Text1', 'hello'))

    status = _validate(out, temp_vc, {'Text1'})
    _assert_crypto_ok(status)
    assert not status.bottom_line
    assert isinstance(status.diff_result, SuspiciousModification)
    assert 'locked' in str(status.diff_result)


def test_permission_policy_receives_signature_and_revision(
    temp_signer, temp_vc
):
    out = _sign_form(temp_signer)
    out = _increment(out, lambda w: _fill_text_field(w, 'Text1', 'hello'))

    requests = []

    class RecordingPolicy(FieldChangePermissionPolicy):
        def check_field_change(self, request):
            requests.append(request)

    r = PdfFileReader(out)
    sig = r.embedded_signatures[0]
    diff_policy = FieldChangeRestrictedDiffPolicy(
        RecordingPolicy(), signature=sig
    )
    status = validate_pdf_signature(sig, temp_vc, diff_policy=diff_policy)
    assert status.bottom_line
    assert len(requests) == 1
    (request,) = requests
    assert request.signature is sig
    assert request.fq_field_name == 'Text1'
    assert request.signed_revision == sig.signed_revision
    assert request.revision == sig.signed_revision + 1


def test_unanalysable_field_tree_not_treated_as_harmless(temp_signer, temp_vc):
    # duplicate partial names in the field tree of the new revision
    # must be rejected, not silently ignored
    out = _sign_form(temp_signer)

    def _mutate(w):
        page_ref = w.root['/Pages']['/Kids'].raw_get(0)
        # add a second field also named "Text1"
        tf_ref = w.add_object(
            _text_field_dict('Text1', page_ref, (10, 10, 130, 30))
        )
        w.root['/AcroForm']['/Fields'].append(tf_ref)
        w.update_container(w.root['/AcroForm'])
        w.register_annotation(page_ref, tf_ref)

    out = _increment(out, _mutate)
    status = _validate(out, temp_vc, {'Text1', 'Text2'})
    _assert_crypto_ok(status)
    assert not status.bottom_line
    assert isinstance(status.diff_result, SuspiciousModification)
    assert 'uplicate' in str(status.diff_result)
