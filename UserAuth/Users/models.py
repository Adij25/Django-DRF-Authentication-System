from django.contrib.auth.models import AbstractUser
from django.db import models 

# Create your models here.4

class User(AbstractUser):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)

    def __str__(self):
        return self.username
    
    


    
    

