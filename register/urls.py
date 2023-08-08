from django.urls import path
from . import views
from .views import takeprofile,reguserprofile


urlpatterns =[
    path('', views.insert_details, name='insert_details'),
    path('usrreg',takeprofile.as_view()),
    path('login/',views.login_view, name='login_view'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('mailcheck/', views.mailid_auth, name='mailid_authentication'),
    path('resetpassword/', views.reset_password, name='reset_password'),
    path('upload/',views.upload_view, name='upload_view'),    
    path('reg/<str:name>',reguserprofile.as_view())
    
]