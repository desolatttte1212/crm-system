from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password



class SecureRegisterForm(forms.Form):
    username = forms.CharField(max_length=150)
    email = forms.EmailField()
    hashed_password = forms.CharField(widget=forms.HiddenInput())

    def save(self):
        user = User.objects.create_user(
            username=self.cleaned_data['username'],
            email=self.cleaned_data['email'],
            password=self.cleaned_data['hashed_password']
        )
        user.password = make_password(self.cleaned_data['hashed_password'])
        user.save()
        return user
from django import forms
from django.contrib.auth.forms import AuthenticationForm

class LoginForm(AuthenticationForm):
    username = forms.CharField(label="Имя пользователя")
    password = forms.CharField(widget=forms.PasswordInput)

