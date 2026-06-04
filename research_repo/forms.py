from django.forms import ModelForm, ValidationError, Form
from django.forms import inlineformset_factory
from django.contrib.auth.forms import UserCreationForm,AuthenticationForm
from .models import Publication, User, AccessGrant, Authorship
import cloudinary.uploader
from django import forms
from django.forms import ModelForm
from .models import Publication



class LoginForm(AuthenticationForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault('class', 'form-control')


class SignUpForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault('class', 'form-control')
        

# changes from forms.py
class PublicationForm(ModelForm):
    class Meta:
        model = Publication
        fields = ['title', 'abstract', 'full_pdf', 'is_public', 'auto_approve_access']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'abstract': forms.Textarea(attrs={'class': 'form-control', 'rows': 6}),
            'full_pdf': forms.FileInput(attrs={'accept': '.pdf', 'class': 'form-control'}),
            'is_public': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'auto_approve_access': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }
# end

class AuthorshipForm(ModelForm):
    class Meta:
        model = Authorship
        fields = ['user', 'contribution_role']
        widgets = {
            'user': forms.Select(attrs={'class': 'form-control'}),
            'contribution_role': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. Co-author, Data analyst'}),
        }

AuthorshipFormSet = inlineformset_factory(Publication, Authorship, form=AuthorshipForm, extra=1, can_delete=True)


class UploadDocumentForm(Form):
    class Meta:
        fields = ['title', 'abstract', 'full_pdf', 'is_public', 'auto_approve_access']

    def clean_full_pdf_url(self):
        file = self.cleaned_data.get('full_pdf')
        if file:
            try:
                result = cloudinary.uploader.upload(file)
                return result['secure_url']
            except Exception as e:
                raise ValidationError(f"File upload failed: {str(e)}")
        raise ValidationError("No file provided.")
    
class AccessGrantForm(ModelForm):
    class Meta:
        model = AccessGrant
        fields = ['viewer', 'access_granted', 'expires_at']
        widgets = {
            'viewer': forms.Select(attrs={'class': 'form-control'}),
            'access_granted': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'expires_at': forms.DateTimeInput(attrs={'class': 'form-control', 'type': 'datetime-local'}),
        }