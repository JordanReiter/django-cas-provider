from django import forms
from django.conf import settings
from django.contrib.auth import authenticate
from django.forms import ValidationError
from django.utils.translation import ugettext_lazy as _
from models import LoginTicket
import datetime


class LoginForm(forms.Form):
    email = forms.CharField(widget=forms.TextInput(attrs={'autofocus': 'autofocus',
                                                          'placeholder': 'Email',
                                                          'max_length': '255'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'placeholder': 'Password'}))
    service = forms.CharField(widget=forms.HiddenInput, required=False)
    remember_me = forms.BooleanField(required=False, label="Keep me signed in",
                                     widget=forms.CheckboxInput(attrs={'class': 'remember_me'}))

    def __init__(self, *args, **kwargs):
        # renew = kwargs.pop('renew', None)
        # gateway = kwargs.pop('gateway', None)
        request = kwargs.pop('request', None)
        super(LoginForm, self).__init__(*args, **kwargs)
        self.request = request

    def clean_remember_me(self):
        remember = self.cleaned_data['remember_me']
        if not remember and self.request is not None:
            self.request.session.set_expiry(0)


class MergeLoginForm(LoginForm):
    email = forms.CharField(max_length=255, widget=forms.HiddenInput)
