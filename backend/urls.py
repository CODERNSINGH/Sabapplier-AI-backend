from django.contrib import admin

# add include to the path
from django.urls import path, include

# import views from todo
from users import views

# import routers from the REST framework
# it is necessary for routing
# from rest_framework import routers

# create a router object
# router = routers.DefaultRouter()

# register the router
# router.register(r'users',views.users_view, 'users')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/users/', include('users.urls'))
]

# from django.conf import settings
# from django.conf.urls.static import static

# urlpatterns = [
#     path('admin/', admin.site.urls),
#     path('api/users/', include('users.urls')),
# ] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT) 
