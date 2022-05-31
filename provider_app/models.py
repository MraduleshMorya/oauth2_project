from pyexpat import model
from django.db import models

# Create your models here.


class login_with_records(models.Model):
    username = models.CharField(max_length=150,null=True,blank=True)
    application_name = models.CharField(max_length=100,null=True,blank=True)
    date_time = models.DateTimeField(auto_now_add=True,editable=False)
    permission = models.BooleanField(null=True, blank=True)
    status = models.BooleanField(null=True, blank=True)
    date = models.DateField(auto_now_add=True)
    time = models.TimeField(auto_now_add=True)
    auth_token = models.CharField(max_length=60, null=True, blank=True)
    access_token = models.CharField(max_length=500, null=True,blank=True)
    
    def __str__(self):
        return f"{self.username}-{self.application_name}-{self.date_time}"
