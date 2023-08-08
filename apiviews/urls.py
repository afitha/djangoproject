from django.urls import path
from apiviews import views
from .views import takeprofile,takeuserprofile

urlpatterns = [
    path('alluser',takeprofile.as_view()),
    path('usr/<str:email>',takeuserprofile.as_view()),
    
]
