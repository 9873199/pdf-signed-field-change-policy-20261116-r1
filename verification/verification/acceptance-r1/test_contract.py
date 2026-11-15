"""Prepared independent contracts; final public API must be mapped after freeze."""
import pytest
from pyhanko.pdf_utils import generic
from pdf_fixtures import make_signed,revise,field,fill,signature,validate
from reviewer_adapter import permit

FIRST='TextInput.TextField1'
SECOND='TextInput.TextField2'

def crypto_valid(data,root):
    status=validate(data,root)
    assert status.intact and status.valid and status.trusted

def deny(data,root,allowed):
    crypto_valid(data,root)
    approved,reason=permit(data,root,allowed)
    assert approved is False
    assert reason, 'Rejected changes must have field/object diagnostics'

def test_authorized_existing_text_value_and_appearance():
    data,root=make_signed();changed=revise(data,lambda w:fill(w,0,'allowed'))
    crypto_valid(changed,root)
    assert permit(changed,root,{FIRST})[0] is True

@pytest.mark.parametrize('allowed',[set(),{FIRST}])
def test_other_field_is_not_authorized_by_first_field(allowed):
    data,root=make_signed();changed=revise(data,lambda w:fill(w,1,'unauthorized'))
    deny(changed,root,allowed)

def test_default_validation_keeps_legacy_form_filling():
    data,root=make_signed();changed=revise(data,lambda w:fill(w,1,'legacy'))
    status=validate(changed,root)
    assert status.intact and status.valid and status.docmdp_ok

def mutate(writer,kind):
    obj=field(writer,0)
    if kind=='rename':obj['/T']=generic.pdf_string('renamed')
    elif kind=='type':obj['/FT']=generic.pdf_name('/Btn')
    elif kind=='action':
        obj['/AA']=generic.DictionaryObject({generic.pdf_name('/K'):generic.DictionaryObject({generic.pdf_name('/S'):generic.pdf_name('/JavaScript'),generic.pdf_name('/JS'):generic.pdf_string('void(0)')})})
    elif kind=='page':obj['/P']=writer.add_object(generic.DictionaryObject())
    elif kind in ('duplicate','new-field'):
        parent=writer.root['/AcroForm']['/Fields'][1].get_object()
        new=generic.DictionaryObject(dict(obj))
        if kind=='new-field':new['/T']=generic.pdf_string('newfield')
        parent['/Kids'].append(writer.add_object(new));writer.update_container(parent)
    else:raise AssertionError(kind)
    writer.update_container(obj)

@pytest.mark.parametrize('kind',['rename','type','action','page','duplicate','new-field'])
def test_allowing_text_does_not_authorize_structure_or_actions(kind):
    data,root=make_signed();changed=revise(data,lambda w:mutate(w,kind))
    deny(changed,root,{FIRST,SECOND})

def test_bad_intermediate_revision_is_not_erased_by_reverting_final_object():
    data,root=make_signed()
    changed=revise(data,lambda w:mutate(w,'rename'))
    def revert(w):
        obj=field(w,0);obj['/T']=generic.pdf_string('TextField1');w.update_container(obj)
    reverted=revise(changed,revert)
    deny(reverted,root,{FIRST,SECOND})

def test_permission_cannot_override_docmdp_no_changes():
    data,root=make_signed(no_changes=True)
    changed=revise(data,lambda w:fill(w,0,'forbidden'))
    deny(changed,root,{FIRST,SECOND})

def test_shared_appearance_requires_permission_for_all_affected_fields():
    data,root=make_signed(shared=True)
    def change(w):
        stream=field(w,0)['/AP']['/N']
        stream._data=b'q 0 0 1 rg BT /Ti 12 Tf (shared change) Tj ET Q'
        stream._encoded_data=None
        w.update_container(stream)
    changed=revise(data,change)
    deny(changed,root,{FIRST})
