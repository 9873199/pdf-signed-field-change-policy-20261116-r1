"""Reviewer-only signed PDF revisions. Keys stay in memory; no viewer/network."""
from datetime import datetime,timedelta,timezone
from io import BytesIO
from cryptography import x509 as cx
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from asn1crypto import x509,keys
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.content import RawContent
from pyhanko.pdf_utils.layout import BoxConstraints
from pyhanko.sign import signers,fields
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore
from pyhanko_testing_commons.test_data.samples import TEXTFIELD_GROUP

def make_signer():
    now=datetime.now(timezone.utc)
    root_key=ec.generate_private_key(ec.SECP256R1());leaf_key=ec.generate_private_key(ec.SECP256R1())
    root_name=cx.Name([cx.NameAttribute(NameOID.COMMON_NAME,'Temporary review CA')])
    leaf_name=cx.Name([cx.NameAttribute(NameOID.COMMON_NAME,'Temporary PDF signer')])
    def builder(subject,issuer,public):
        return cx.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public).serial_number(cx.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=2))
    root=builder(root_name,root_name,root_key.public_key()).add_extension(cx.BasicConstraints(ca=True,path_length=0),True).add_extension(cx.KeyUsage(False,False,False,False,False,True,True,False,False),True).sign(root_key,hashes.SHA256())
    leaf=builder(leaf_name,root_name,leaf_key.public_key()).add_extension(cx.BasicConstraints(ca=False,path_length=None),True).add_extension(cx.KeyUsage(True,True,False,False,False,False,False,False,False),True).sign(root_key,hashes.SHA256())
    root_asn=x509.Certificate.load(root.public_bytes(serialization.Encoding.DER))
    leaf_asn=x509.Certificate.load(leaf.public_bytes(serialization.Encoding.DER))
    key_asn=keys.PrivateKeyInfo.load(leaf_key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    signer=signers.SimpleSigner(leaf_asn,key_asn,cert_registry=SimpleCertificateStore.from_certs([root_asn]))
    return signer,root_asn

def field_ref(writer,index):
    parent=writer.root['/AcroForm']['/Fields'][1].get_object()
    return parent['/Kids'].raw_get(index)

def field(writer,index):return field_ref(writer,index).get_object()

def fill(writer,index,value):
    target=field(writer,index)
    target['/V']=generic.pdf_string(value)
    appearance=RawContent(box=BoxConstraints(height=60,width=130),data=b'q 0 0 1 rg BT /Ti 12 Tf ('+value.encode('ascii')+b') Tj ET Q')
    target['/AP']=generic.DictionaryObject({generic.pdf_name('/N'):writer.add_object(appearance.as_form_xobject())})
    writer.update_container(target)

def make_signed(*,no_changes=False,shared=False):
    signer,root=make_signer();writer=IncrementalPdfFileWriter(BytesIO(TEXTFIELD_GROUP))
    fill(writer,0,'first');fill(writer,1,'second')
    if shared:
        field(writer,1)['/AP']=field(writer,0)['/AP'];writer.update_container(field(writer,1))
    meta=signers.PdfSignatureMetadata(field_name='Sig1',certify=True,docmdp_permissions=fields.MDPPerm.NO_CHANGES if no_changes else fields.MDPPerm.FILL_FORMS)
    stream=signers.sign_pdf(writer,meta,signer=signer)
    return stream.getvalue(),root

def revise(data,operation):
    writer=IncrementalPdfFileWriter(BytesIO(data));operation(writer)
    result=BytesIO();writer.write(result);return result.getvalue()

def signature(data):return PdfFileReader(BytesIO(data)).embedded_signatures[0]

def validate(data,root,**kwargs):
    vc=ValidationContext(trust_roots=[root],allow_fetching=False,revocation_mode='soft-fail')
    return validate_pdf_signature(signature(data),signer_validation_context=vc,**kwargs)

if __name__=='__main__':
    data,root=make_signed();base=validate(data,root)
    assert base.intact and base.valid and base.trusted and base.docmdp_ok
    changed=revise(data,lambda w:fill(w,0,'updated'))
    status=validate(changed,root)
    assert status.intact and status.valid and status.trusted and status.docmdp_ok
    print('Temporary EC CA and real certified PDF valid; text field incremental fill keeps signature intact and default DocMDP valid; no network.')
