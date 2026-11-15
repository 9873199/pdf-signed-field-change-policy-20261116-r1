import logging
from pdf_fixtures import make_signed,revise,fill,validate,field
from reviewer_adapter import permit
from pyhanko.pdf_utils import generic
logging.disable(logging.CRITICAL)
first='TextInput.TextField1'
data,root=make_signed()
changed=revise(data,lambda w:fill(w,0,'authorized'))
status=validate(changed,root)
print('Real certified PDF signed by a temporary local CA')
print('Cryptographic signature intact/valid/trusted:',status.intact,status.valid,status.trusted)
print('Allowed text field accepted:',permit(changed,root,{first})[0])
other=revise(data,lambda w:fill(w,1,'unlisted'))
print('Unlisted text field rejected:',not permit(other,root,{first})[0])
def rename(w,value):
    obj=field(w,0);obj['/T']=generic.pdf_string(value);w.update_container(obj)
bad=revise(data,lambda w:rename(w,'renamed'))
reverted=revise(bad,lambda w:rename(w,'TextField1'))
print('Forbidden intermediate rename, then revert: rejected =',not permit(reverted,root,{first})[0])
shared,root2=make_signed(shared=True)
def alter(w):
    stream=field(w,0)['/AP']['/N'];stream._data=b'q Q';stream._encoded_data=None;w.update_container(stream)
shared=revise(shared,alter)
print('Shared appearance, only first field allowed: rejected =',not permit(shared,root2,{first})[0])
print('Default form-filling behavior unchanged:',validate(other,root).docmdp_ok)
