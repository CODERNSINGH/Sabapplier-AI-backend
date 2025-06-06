from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import get_user_model, authenticate, login, logout
from .serializers import UserSerializer, TokenSerializer, UserRegistrationSerializer
from datetime import datetime, timedelta
from rest_framework import viewsets
from .models import user, Token
from .apis.ocr_endpoint import get_ocr_data
from .apis.fetch_autofill_data import get_autofill_data

class users_view(viewsets.ModelViewSet):
    serializer_class = UserSerializer
    queryset = user.objects.all()
    
User = get_user_model()


######################  API End Points for Website UI ####################


@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    print(request.data)
    # Ignore extra fields and only process email and password (and confirmPassword if present)
    allowed_fields = {'email', 'password', 'confirmPassword'}
    data = {k: v for k, v in request.data.items() if k in allowed_fields}
    if 'confirmPassword' in data and data['password'] != data['confirmPassword']:
        return Response({'success': False, 'message': 'Passwords do not match.'}, status=status.HTTP_400_BAD_REQUEST)
    serializer = UserSerializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response(
            {"success": True, "message": "You are now registered on our website!"},
            status=status.HTTP_200_OK,
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def update_data(request):
    print(request.data)
    print(request.data.get("email", ""))
    try:
        userData = request.data.copy()
        usr = user.objects.filter(email=userData.get('email', "")).first()
        if (request.data.get("password", "")!=""):
            usr.password= request.data.get("password", "")
            usr.save()
            userData.pop("password")
        for field_name, uploaded_file in request.FILES.items():
            text_field_name = field_name.replace('_file_url', '_text')
            userData[text_field_name] = get_ocr_data(uploaded_file)
        serializer = UserSerializer(usr, data=userData, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"success": True, "message": "You are now registered on our website!"},
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as err:
        print(err)
        return Response(
            {"success": False, "message": "error"},
            status=status.HTTP_400_BAD_REQUEST
        )
        
        
@api_view(['POST'])
@permission_classes([AllowAny])
def delete_data(request):
    print(request.data)
    print(request.data.get("email", ""))
    try:
        userData = request.data.copy()
        usr = user.objects.filter(email=userData.get('email', "")).first()
        field = request.data.get('field')

        if not field:
            return Response({"error": "Field name required."}, status=status.HTTP_400_BAD_REQUEST)

        if hasattr(usr, field):
            setattr(usr, field, "")
            setattr(usr, field.replace("_file_url", "_text"), "")
            usr.save()
            return Response({"success": True, "message": f"{field} deleted."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid field."}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    
@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    email = request.data.get('email')
    password = request.data.get('password')
    try:
        usr = user.objects.get(email=email)
        if (usr is None) or (usr.password != password):
            return Response(
                {
                    "success": False,
                    "message": "Invalid user Credentials!",
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )
        else:
            return Response(
                {"success": True, "message": "You are now logged in!"},
                status=status.HTTP_200_OK,
            )
    except user.DoesNotExist:
        return Response(
            {"success": False, "message": "User does not exist"},
            status=status.HTTP_404_NOT_FOUND,
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def logout_view(request):
    try:
        request.session.flush()
        return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
    except:
        return Response({"error": "Logout failed"}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([AllowAny])
def get_profile(request):
    try:
        usr = user.objects.get(email=request.GET.get('email'))
        serializer = UserSerializer(usr)
        user_data = serializer.data 
        print('user_data:', user_data)
        return Response({"message": "Profile fetched successfully", "user_data": user_data}, status=status.HTTP_200_OK) 
    except Exception as err:
        print(err)
        return Response({"error": "profile failed to load"}, status=status.HTTP_400_BAD_REQUEST)




####################  API End Points for Extension ####################


# combine login and auto-fill logic for extension

@api_view(['POST'])
@permission_classes([AllowAny])
def extension_login_view(request):
    try:
        # extract email, password, html_data, and user_email from request data
        email = request.data.get('user_email')
        password = request.data.get('user_password')
        html_data = request.data.get('html_data')
        # print(html_data)
        # user_email = request.data['user_email']


        try:
            usr = user.objects.get(email=email)
            if (usr is None) or (usr.password != password):
                return Response(
                    {
                        "success": False,
                        "message": "Invalid user Credentials!",
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )
            else:

                ## Details Filling Logic or Auto-fill Logic
                print('User exists, proceeding with auto-fill')
                print(usr)
                try:
                    usr = user.objects.get(email=email)
                    user_data = UserSerializer(usr).data
                    print('user_data:', user_data)
                    autofill_data = get_autofill_data(html_data, user_data)
                    print('autofill_data:', autofill_data)

                    #Generate Tokens
                    # token, created = Token.objects.create(user=usr, token="your_token_value")
                    # if created:
                    #     print('Token created successfully')
                    # else:
                    #     print('Issue')



                    return Response({"message": "Auto-fill successful", "autofill_data": autofill_data, "success": True, "message": "You are now logged in!", "user_name": usr.fullname, "user_email": usr.email }, status=status.HTTP_200_OK)
                    # return Response({"message": "Auto-fill successful", "autofill_data": autofill_data, "success": True, "message": "You are now logged in!"}, status=status.HTTP_200_OK)
                
                except user.DoesNotExist:
                    print('User does not exist...')
                    return Response({"message": "User not found", "autofill_data": {}}, status=status.HTTP_404_NOT_FOUND)


                # return Response(
                #     {"success": True, "message": "You are now logged in!", "refresh_token": refresh, "access_token": access_token},
                #     status=status.HTTP_200_OK,
                # )


        except user.DoesNotExist:
            return Response(
                {"success": False, "message": "User does not exist"},
                status=status.HTTP_404_NOT_FOUND,
            )
    except Exception as err:
        print('Error:', err)
        return Response({"error": "Auto-fill failed"}, status=status.HTTP_400_BAD_REQUEST)
    


@api_view(['POST'])
@permission_classes([AllowAny])
def auto_fill_extension(request):
    try:
        html_data = request.data['html_data']
        user_email = request.data['user_email']
        try:
            usr = user.objects.get(email=user_email)
            user_data = UserSerializer(usr).data
            print('user_data:', user_data)
            autofill_data = get_autofill_data(html_data, user_data)
            print('autofill_data:', autofill_data)
            return Response({"message": "Auto-fill successful", "autofill_data": autofill_data, "user_name": usr.fullname, "user_email": usr.email}, status=status.HTTP_200_OK)
        except user.DoesNotExist:
            print('User does not exist...')
            return Response({"message": "User not found", "autofill_data": {}}, status=status.HTTP_404_OK)
    except Exception as err:
        print('Error:', err)
        return Response({"error": "Auto-fill failed"}, status=status.HTTP_400_BAD_REQUEST)
 


# Token Based Auto-fill Logic Future Implementation

# @api_view(['POST'])
# @permission_classes([IsAuthenticated])
# def validate_token(request):
#     try:
#         html_data = request.data['html_data']
#         user_email = request.user.email  # Get the email from the authenticated user

#         try:
#             usr = User.objects.get(email=user_email)
#             user_data = UserSerializer(usr).data
#             print('user_data:', user_data)
#             autofill_data = get_autofill_data(html_data, user_data)
#             print('autofill_data:', autofill_data)
#             return Response({"message": "Auto-fill successful", "autofill_data": autofill_data}, status=status.HTTP_200_OK)
#         except User.DoesNotExist:
#             print('User does not exist...')
#             return Response({"message": "User not found", "autofill_data": {}}, status=status.HTTP_404_NOT_FOUND)
#     except Exception as err:
#         print('Error:', err)
#         return Response({"error": "Auto-fill failed"}, status=status.HTTP_400_BAD_REQUEST)