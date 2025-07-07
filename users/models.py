from django.db import models
import os

class Token(models.Model):
    id = models.AutoField(primary_key=True)
    token = models.CharField(max_length=255)
    created_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    user_id = models.IntegerField()
    is_used = models.BooleanField(default=False)
    
def passport_size_photo_upload_path(instance, filename):
    ext = filename.split('.')[-1] # Get the file extension
    filename = f"{instance.email.split('@')[0]}_passport_size_photo.{ext}" 
    return os.path.join("passport_size_photos", filename)

def aadhaar_card_upload_path(instance, filename):
    ext = filename.split('.')[-1] # Get the file extension
    filename = f"{instance.email.split('@')[0]}_aadhaar_card.{ext}" 
    return os.path.join("aadhaar_cards", filename)

def pan_card_upload_path(instance, filename):
    ext = filename.split('.')[-1] # Get the file extension
    filename = f"{instance.email.split('@')[0]}_pan_card.{ext}" 
    return os.path.join("pan_cards", filename)

def signature_upload_path(instance, filename):
    ext = filename.split('.')[-1] # Get the file extension
    filename = f"{instance.email.split('@')[0]}_signature.{ext}" 
    return os.path.join("signatures", filename)

def _10th_certificate_upload_path(instance, filename):
    ext = filename.split('.')[-1] # Get the file extension
    filename = f"{instance.email.split('@')[0]}_10th_certificate.{ext}" 
    return os.path.join("_10th_certificates", filename)

def _12th_certificate_upload_path(instance, filename):
    ext = filename.split('.')[-1] # Get the file extension
    filename = f"{instance.email.split('@')[0]}_12th_certificate.{ext}" 
    return os.path.join("_12th_certificates", filename)

def graduation_certificate_upload_path(instance, filename):
    ext = filename.split('.')[-1] # Get the file extension
    filename = f"{instance.email.split('@')[0]}_graduation_certificate.{ext}" 
    return os.path.join("graduation_certificate", filename)
   
class user(models.Model):     
    Gender_Choices = [
        ('Select', 'Select'),
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Other', 'Other'),
    ]
    Category_Choices = [
        ('Select', 'Select'),
        ('GEN', 'GEN'),
        ('OBC', 'OBC'),
        ('SC', 'SC'),
        ('ST', 'ST'),
        ('EWS', 'EWS'),
    ]
    MaritalStatus_Choices = [
        ('Select', 'Select'),
        ('Single', 'Single'),
        ('Married', 'Married'),
        ('Divorced', 'Divorced'),
        ('Widowed', 'Widowed'),
        ('Others', 'Others'),
    ]
    
      # id = models.AutoField(primary_key=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    fullName = models.CharField(max_length=255, null=True)
    fathersName = models.CharField(max_length=255, null=True)
    mothersName = models.CharField(max_length=255, null=True)
    gender = models.CharField(max_length=10, choices=Gender_Choices, default='Select')
    dateofbirth = models.DateField(null=True)
    category = models.CharField(max_length=10, choices=Category_Choices, default='Select')
    disability = models.BooleanField(default=False)
    nationality = models.CharField(max_length=255, null=True)
    domicileState = models.CharField(max_length=255, null=True)
    district = models.CharField(max_length=255, null=True)
    mandal = models.CharField(max_length=255, null=True)
    pincode = models.CharField(max_length=6, null=True)
    maritalStatus = models.CharField(max_length=255, choices=MaritalStatus_Choices, default='Select')
    religion = models.CharField(max_length=255, null=True)
    permanentAddress = models.TextField(null=True)
    correspondenceAddress = models.TextField(null=True)
    phone_number = models.CharField(max_length=10, null=True)
    alt_phone_number = models.CharField(max_length=10, null=True)
    google_profile_picture = models.URLField(null=True, blank=True)  # Store Google profile picture URL
    document_urls = models.JSONField(default=dict, null=True)
    document_texts = models.JSONField(default=dict, null=True)
    extra_details = models.JSONField(default=list, null=True, blank=True)

    def __str__(self):
        return self.email
