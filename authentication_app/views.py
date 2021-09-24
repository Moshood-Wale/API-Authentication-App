from logging import raiseExceptions
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import generics,status,permissions, views
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from .models import User,generate_otp
from .serializers import GenerateOTPSerializer,VerifyOTPSerializer,UserSerializer,LogoutSerializer
from .utils import Util
from django.contrib.auth import get_user_model
from rest_framework import permissions
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str,smart_bytes,force_str,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util
from rest_framework.authtoken.serializers import AuthTokenSerializer 
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.views import APIView
from django.contrib.auth import get_user_model, logout

class RegisterView(generics.ListCreateAPIView):
    permission_classes=(permissions.AllowAny,)
    serializer_class = UserSerializer
    queryset=User.objects.all()
    def post(self,request):
        user=request.data
        serializer=self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True) 
        
        serializer.save() 
        email = request.data.get('email')
        
        code = generate_otp()
        user = get_user_model().objects.get(email=email)
        user.otp_code=code
        user.save()
        token=code
        email_body=f'Hi{user.username}\n Please copy the code below to verify your email \n {token}'
        data={'email_body':email_body,'to_email':[user.email],'email_subject':'Verify your email'}
        Util.send_email(data)
        user_data=serializer.data
        user=User.objects.get(email=user_data['email'])
        token=RefreshToken.for_user(user).access_token
        user.save()
       
        return Response(user_data,status=status.HTTP_201_CREATED)
    

class VerifyOTPView(generics.CreateAPIView):
    serializer_class=VerifyOTPSerializer
    
    def get(self,request):
        return Response({'message':"please enter the cerification code that was sent to your mail"})
    
    def post(self,request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            print('\n', serializer.data.get('otp_code'))
        
        token = serializer.data.get('otp_code')
       
        try:
            
            user=User.objects.get(otp_code=token) 
           
            if not user.verification:
                user.verification=True
                user.otp_code=token
                user.save()
                return Response({'email':'Succesfully Activated'},status=status.HTTP_200_OK)
        except:
            return Response({'error':'Account not verified. Please provide a valid code'},
                            status=status.HTTP_400_BAD_REQUEST)
    
    
    
    
    
class GenerateOTPVIew(generics.ListCreateAPIView):
    permission_classes=(permissions.IsAuthenticated,)
    queryset=User.objects.all()
    serializer_class=GenerateOTPSerializer
    
    def post(self,request):
        try:
            email = request.data.get('email')
        
            code = generate_otp()
            user = get_user_model().objects.get(email=email)
            user.otp_code=code
            user.save()
            token=code
            email_body=f'Hi{user.username}\n Please copy the code below to verify your email \n {token}'
            data={'email_body':email_body,'to_email':[user.email],'email_subject':'Verify your email'}
            Util.send_email(data)
            return Response({"otp_code":code},status=status.HTTP_201_CREATED)
        except :
            return Response({"message":"User does not exist"}, status=404)
    

class VerifyOTPView(generics.CreateAPIView):
    permission_classes=(permissions.IsAuthenticated,)
    serializer_class=VerifyOTPSerializer
    def get(self,request):
        return Response({'message':"please enter the cerification code hat was sent to your mail"})
    def post(self,request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            print('\n', serializer.data.get('otp_code'))
        
        token = serializer.data.get('otp_code')
        try:
            
            user=User.objects.get(otp_code=token)
           
           
            if not user.verification:
                user.verification=True
                user.otp_code=token
                user.save()
                return Response({'email':'Succesfully Activated'},status=status.HTTP_200_OK)
        except:
            return Response({'error':'Account not verified. Please provide a valid code'},
                            status=status.HTTP_400_BAD_REQUEST)  
   
 

class LoginViews(generics.GenericAPIView):
    
    serializer_class = AuthTokenSerializer 
    
    
    def post(self, request):
        return ObtainAuthToken().as_view()(request=request._request)


class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer

    permission_classes = (permissions.IsAuthenticated,)
    
    
    def post(self, request):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)
