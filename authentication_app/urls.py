from django.urls import path
from.views import RegisterView,VerifyOTPView,GenerateOTPVIew, LoginViews, LogoutAPIView

urlpatterns=[
   
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginViews.as_view(), name='login'),
    path('generate-otp/', GenerateOTPVIew.as_view(), name='generate_otp'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    
       
]