from django.db import models
import uuid

# Create your models here.

class Video(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False )
    name= models.CharField(max_length=500)
    selector = models.CharField(max_length=100, default="google")
    geeks_field = models.TimeField(auto_now=True)
    videofile= models.FileField(upload_to='eml/', null=True, verbose_name="")
    
    def __str__(self):
        return str(self.videofile)

class Piechart(models.Model):
    ldmarc_rel = models.BooleanField(default = True) 
