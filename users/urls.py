from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from . import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path('register/', views.register, name='register'),
    path('update/', views.update_data, name='update_data'),
    path('delete/', views.delete_data, name='delete_data'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.get_profile, name='profile'),
    path('profile/<str:email>/', views.get_profile, name='profile'),

    # extension paths
    

    path('extension/login/', views.extension_login_view, name="extension_login_view"), #User login for extension
    path('extension/auto-fill/', views.auto_fill_extension, name='validate_token'),  # Mail Based Auth Auto Fill


    # API Token Based Auth Future Plan
    
    # path('extension/auto-fill/', views.auto_fill_extension, name='auto-fill-extension'), # will be removed soon
   # path('token/refresh/auto-fill/', TokenRefreshView.as_view(), name='token_refresh'),  # Adding API Token Based Auth Refresh
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root = settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root = settings.STATIC_URL)
