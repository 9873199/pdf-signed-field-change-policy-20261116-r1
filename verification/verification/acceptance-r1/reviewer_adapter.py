from pyhanko.sign.diff_analysis import FieldChangeRestrictedDiffPolicy,WhitelistFieldChangePolicy
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from pdf_fixtures import signature
def permit(data,root,allowed):
    sig=signature(data)
    policy=FieldChangeRestrictedDiffPolicy(WhitelistFieldChangePolicy(allowed),signature=sig)
    vc=ValidationContext(trust_roots=[root],allow_fetching=False,revocation_mode='soft-fail')
    result=validate_pdf_signature(sig,signer_validation_context=vc,diff_policy=policy)
    assert result.intact and result.valid and result.trusted
    return bool(result.docmdp_ok),str(result.diff_result)
