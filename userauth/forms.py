from django import forms
from django.contrib.auth.forms import UserCreationForm
from userauth.models import User

class UserRegistrationForm(UserCreationForm):

    #This is the form that will be used to register a new user
    username = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "style": "padding:5px; border-width:1px; border-color:gray; width:300px; border-radius:7px;",
                "placeholder": "Username",
            }
        )
    )
    email = forms.EmailField(
        widget=forms.EmailInput(
            attrs={
                "style": "padding:5px; border-width:1px; border-color:gray; width:300px; border-radius:7px;",
                "placeholder": "Email Address",
            }
        )
    )
    password1 = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "style": "padding:5px; border-width:1px; border-color:gray; width:300px; border-radius:7px;",
                "placeholder": "Password",
            }
        )
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "style": "padding:5px; border-width:1px; border-color:gray; width:300px; border-radius:7px;",
                "placeholder": "Confirm Password",
            }
        )
    )
    role = forms.ChoiceField(
        required=True,
        choices=User.ROLE_CHOICES,
        widget=forms.Select(
            attrs={
                "style": "padding:5px; border-width:1px; border-color:gray; width:300px; border-radius:7px;",
            }
        )
    )
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2', 'role']

    #This checks for existing user credentials in the system
    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username__iexact=username).exists():
            raise forms.ValidationError("A user with that username already exists.")
        return username

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("A user with that email already exists.")
        return email