from django.shortcuts import render
from urllib import response
from rest_framework.decorators import APIView
from django.http import JsonResponse
from django.http import HttpResponse
from rest_framework.response import Response
import requests
from rest_framework import status
import configparser


# Create your views here.

import pymongo
from pymongo import MongoClient

# Connecting to MongoDB Atlas
# client = pymongo.MongoClient('mongodb+srv://ansarafitha:root@cluster0.vgtdfso.mongodb.net/test')
# Read the URL from the text file
config=configparser.ConfigParser()
config.read('config.ini')
mongo_url=config.get("mongodb","mongourl")
data_name=config.get("mongodb","database")

# Access MongoDB using the obtained URL
client = pymongo.MongoClient(mongo_url)
# Creating database and collection objects
mydb = client[data_name]
mycol = mydb['flag']

# Define the API view for getting and deleting all profiles
class takeprofile(APIView):
     # GET method to retrieve all profiles
    def get(self, request):
        try:
            # Find all profiles in the database and exclude the ID field
            mydoc = mycol.find({},{"_id": 0,"processed_message_id":0})
            result = []
            for x in mydoc:
                result.append(x)
            # Return the profiles as a JSON response
            return JsonResponse(result, safe=False,status=200)
        except Exception as e:
            # Handle the exception or log the error
            return JsonResponse({"error": str(e)},status=500)

        
    # DELETE method to delete all profiles
    def delete(self,request):
        try:
            # Delete all profiles in the database
            mydoc= mycol.delete_many({})
            # Return a message indicating the database is now empty
            return JsonResponse({"message": "MongoDB is Empty."},status=200)
        except Exception as e:
            # Handle the exception or log the error
            return JsonResponse({"error": str(e)},status=500)
        
        
        
    
# Define the API view for getting, updating, and deleting individual profiles
class takeuserprofile(APIView):
    
    # GET method to retrieve a profile by name
    def get(self, request, email):
        try:
            if not email:
                return JsonResponse({"error": "Name parameter is missing."},status=400)
            # Find the profile in the database by name and exclude the ID field
            mydoc = mycol.find({"email": email}, {"_id": 0, "processed_message_id": 0})
            result = []
            for x in mydoc:
                result.append(x)
            # Return the profile as a JSON response
            return JsonResponse(result, safe=False,status=200)
        except Exception as e:
            # Handle the exception or log the error
            return JsonResponse({"error": str(e)},status=500)
        
    # DELETE method to delete a profile by name  
    def delete(self,request,email):
        try:
            if not email:
                return JsonResponse({"error": "Name parameter is missing."},status=400)
            # Delete the profile in the database by name
            mydoc= mycol.delete_one({"email":email})
            mydic = mycol.find({},{"_id": 0,"processed_message_id":0})
            result = []
            for x in mydic:
                result.append(x)
            # Return all profiles as a JSON response
            return JsonResponse(result, safe=False,status=200)
        except Exception as e:
            # Handle the exception or log the error
            return JsonResponse({"error": str(e)},status=500)
