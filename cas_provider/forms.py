from django import forms


class LoginForm(forms.Form):
    email = forms.CharField(
        widget=forms.TextInput(
            attrs={'autofocus': 'autofocus',
                   'max_length': '255'})
    )
    password = forms.CharField(widget=forms.PasswordInput())
    service = forms.CharField(widget=forms.HiddenInput, required=False)
    remember_me = forms.BooleanField(
        required=False,
        label="Keep me signed in",
        widget=forms.CheckboxInput(
            attrs={'class': 'remember_me'})
    )

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
