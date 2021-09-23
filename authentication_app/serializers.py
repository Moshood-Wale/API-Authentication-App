from django.db.models import fields
from django.http import request
from authentication_app.models import User
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib import auth
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str,smart_bytes,force_str,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode




class UserSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = get_user_model()
        fields = ( 'id','username','email','password',)
        extra_kwargs = {'password': {'write_only': True, 'min_length': 5}}
        
        def validate(self, attrs):
            email=attrs.get('email','')
        
            return super().validate(attrs)

    def create(self, validated_data):
        """Create a new user with encrypted password and return it"""
        return get_user_model().objects.create_user(**validated_data)
    
    
class GenerateOTPSerializer(serializers.ModelSerializer):
    email=serializers.EmailField()
    
    class Meta:
        model=User
        fields=('id','email',)
        
    def validate(self, attrs):
        email=attrs.get('email','')
        
        return super().validate(attrs)
    
class VerifyOTPSerializer(serializers.Serializer):    
    
    otp_code=serializers.CharField(max_length=5)
    


    
class LoginSerializers(serializers.ModelSerializer):
    
    email=serializers.CharField(max_length=100)
    password=serializers.CharField(max_length=60,min_length=6)
    # write_only=True
    class Meta:
        model=User
        fields=['email','password']
        
    def _validate_entries(self, email, password):
        user = None
        if email and password and User.objects.filter(email=email).exists():
            user = auth.authenticate(email=email, password=password) 
            check_verification= User.objects.filter(email=email)[0]
            print(check_verification.verification) 
            if check_verification.verification:
                    
                return "login successful"
            else:
                raise AuthenticationFailed('You are not verified')            
        else:
            raise AuthenticationFailed('Invalid credentials,Please try again')
        
    def validate(self, attrs):
        password = attrs.get('password')
        email = attrs.get('email')
        user = self._validate_entries(email, password)
        attrs['user'] = user
        return attrs

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_message = {
        'bad_token': ('Token is expired or invalid')
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):

        try:
            RefreshToken(self.token).blacklist()

        except TokenError:
            
            self.fail('bad_token') 
            
    
