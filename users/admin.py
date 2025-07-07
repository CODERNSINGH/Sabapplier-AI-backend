from django.contrib import admin

from .models import user, Token

class usersAdmin(admin.ModelAdmin):
    list_display=('email', 'password', 'fullName', 'fathersName', 'mothersName', 'gender', 'dateofbirth', 'category', 'disability', 'nationality', 'domicileState', 'maritalStatus', 'religion', 'permanentAddress', 'correspondenceAddress', 'phone_number', 'alt_phone_number', 'document_urls', 'document_texts')
    search_fields=('email', 'password', 'fullName', 'fathersName', 'mothersName', 'gender', 'dateofbirth', 'category', 'disability', 'nationality', 'domicileState', 'maritalStatus', 'religion', 'permanentAddress', 'correspondenceAddress', 'phone_number', 'alt_phone_number', 'document_urls', 'document_texts')
    list_filter=('email', 'password', 'fullName', 'fathersName', 'mothersName', 'gender', 'dateofbirth', 'category', 'disability', 'nationality', 'domicileState', 'maritalStatus', 'religion', 'permanentAddress', 'correspondenceAddress', 'phone_number', 'alt_phone_number', 'document_urls', 'document_texts')
    list_per_page=10

admin.site.register(user,usersAdmin)
admin.site.register(Token)


