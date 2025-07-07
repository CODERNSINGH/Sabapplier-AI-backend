from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from . import views

urlpatterns = [
    # OTP endpoints
    path('send-otp/', views.send_otp, name='send_otp'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    
    # Forgot Password endpoints
    path('forgot-password/send-otp/', views.send_forgot_password_otp, name='send_forgot_password_otp'),
    path('forgot-password/reset/', views.reset_password, name='reset_password'),

    # Google OAuth endpoint
    path('google-signup/', views.google_signup, name='google_signup'),

    # User management endpoints
    path('register/', views.register, name='register'),
    path('update/', views.update_data, name='update_data'),
    path('delete/', views.delete_data, name='delete_data'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.get_profile, name='profile'),
    path('profile/<str:email>/', views.get_profile, name='profile'),
    path('extension/login', views.extension_login_view, name='extension_login_view'),
    path('extension/auto-fill/', views.auto_fill_extension, name='auto-fill-extension'),


    # Learning functionality endpoints
    path('extension/save-learned-data/', views.save_learned_form_data, name='save_learned_data'),
    path('extension/process-learned-data/', views.process_learned_data, name='process_learned_data'),
    path('extension/get-learned-data/', views.get_learned_data, name='get_learned_data'),
    path('extension/delete-learned-data/', views.delete_learned_data, name='delete_learned_data'),
    
    # New popup mode and smart comparison endpoints
    path('extension/toggle-popup-mode/', views.toggle_popup_mode, name='toggle_popup_mode'),
    path('extension/get-popup-mode/', views.get_popup_mode, name='get_popup_mode'),
    path('extension/get-autofill-data/', views.get_user_autofill_data, name='get_user_autofill_data'),
    path('extension/compare-form-data/', views.compare_form_data, name='compare_form_data'),
    path('extension/user-stats/', views.get_user_stats, name='get_user_stats'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root = settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root = settings.STATIC_URL)
