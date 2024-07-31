from django.http import Http404
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import CustomUser, Bus, Route, Booking, BusExpenditure
from .serializers import CustomUserSerializer, BusSerializer, RouteSerializer, BusExpenditureSerializer
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from django.core.mail import send_mail
from django.conf import settings

from rest_framework import generics
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import get_user_model

from .models import CustomUser, BusReview
from .serializers import CustomUserSerializer, LoginSerializer, PasswordResetSerializer, BusReviewSerializer
from django.contrib.auth.tokens import default_token_generator

from rest_framework import generics
from .models import CustomUser
from .serializers import CustomUserSerializer
from .permissions import IsAdminUser, IsStaffUser
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth.forms import SetPasswordForm
from rest_framework.decorators import api_view


User = get_user_model()


from corsheaders.middleware import CorsMiddleware

class CorsMiddleware(CorsMiddleware):
    def process_response(self, request, response):
        response['Access-Control-Allow-Origin'] = 'http://localhost:5173'
        response['Access-Control-Allow-Credentials'] = 'true'
        return response


class AdminOnlyView(generics.ListCreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [IsAdminUser]

class StaffOnlyView(generics.ListCreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [IsStaffUser]


class UserListCreateView(generics.ListCreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.request.method == 'POST':
            self.permission_classes = [AllowAny]
        return super().get_permissions()
    

class PasswordResetRequestView(APIView):
    serializer_class = PasswordResetSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({'success': 'Password reset email has been sent.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class ObtainTokenPairWithRoleView(APIView):
    permission_classes = (AllowAny,)
    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        refresh = RefreshToken.for_user(user)
        return Response({
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "role": user.role
        })

def password_reset_confirm(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = SetPasswordForm(user, request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, 'Your password has been reset successfully. You can now log in with your new password.')
                return redirect('login')  # Redirect to login page after successful password reset
        else:
            form = SetPasswordForm(user)

        return render(request, 'password_reset_confirm.html', {'form': form})
    else:
        messages.error(request, 'The password reset link is invalid or has expired.')
        return redirect('password_reset')  
    
@api_view(['POST'])
def login_view(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data['user']
        
        return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BusList(APIView):
    def get(self, request):
        buses = Bus.objects.all()
        serializer = BusSerializer(buses, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = BusSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class BusDetail(APIView):
    def get_object(self, pk):
        try:
            return Bus.objects.get(pk=pk)
        except Bus.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        bus = self.get_object(pk)
        serializer = BusSerializer(bus)
        return Response(serializer.data)

    def put(self, request, pk):
        bus = self.get_object(pk)
        serializer = BusSerializer(bus, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        bus = self.get_object(pk)
        bus.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class RouteList(APIView):
    def get(self, request):
        routes = Route.objects.all()
        serializer = RouteSerializer(routes, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = RouteSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RouteDetail(APIView):
    def get_object(self, pk):
        try:
            return Route.objects.get(pk=pk)
        except Route.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        route = self.get_object(pk)
        serializer = RouteSerializer(route)
        return Response(serializer.data)

    def put(self, request, pk):
        route = self.get_object(pk)
        serializer = RouteSerializer(route, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        route = self.get_object(pk)
        route.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@csrf_exempt

class BookingListView(APIView):
    def get(self, request):
        bookings = Booking.objects.all()
        serializer = BookingSerializer(bookings, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class BookingDetailView(APIView):
    def get(self, request, pk):
        booking = get_object_or_404(Booking, pk=pk)
        serializer = BookingSerializer(booking)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk):
        booking = get_object_or_404(Booking, pk=pk)
        serializer = BookingSerializer(booking, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Booking updated successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        booking = get_object_or_404(Booking, pk=pk)
        booking.delete()
        return Response({'message': 'Booking deleted successfully'}, status=status.HTTP_204_NO_CONTENT)

class BookingCreateView(APIView):
    def post(self, request):
        serializer = BookingSerializer(data=request.data)
        if serializer.is_valid():
            booking = serializer.save()
            email_content = f"""
            Your booking has been confirmed with the following details:
            
            DATE: {booking.booking_date}
            TIME: {booking.booking_time}
            ROUTE: {booking.booking_route}
            BUS NO.: {booking.booking_bus}
            PASSENGER: {booking.booking_passenger}
            FEE: {booking.booking_fare}
            PAYMENT STATUS: {booking.booking_payment}
            FEE: {booking.booking_fare}
            CONFIRMATION: {booking.booking_confirmation}

            Thank you for choosing our service!

            Best regards,
            RevoTrans
            """
            send_mail(
                'Booking Confirmation',
                email_content,
                settings.DEFAULT_FROM_EMAIL,
                [request.data['booking_email']],
                fail_silently=False,
            )
            return Response({'message': 'Booking created successfully', 'booking_id': booking.booking_id}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
     

class BusExpenditureListCreateView(generics.ListCreateAPIView):
    queryset = BusExpenditure.objects.all()
    serializer_class = BusExpenditureSerializer

class BusExpenditureRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = BusExpenditure.objects.all()
    serializer_class = BusExpenditureSerializer

class BusReviewListCreateView(generics.ListCreateAPIView):
    queryset = BusReview.objects.all()
    serializer_class = BusReviewSerializer

class BusReviewRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = BusReview.objects.all()
    serializer_class = BusReviewSerializer

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import BookingSerializer
from .models import Booking

class BookingListView(APIView):
    def get(self, request):
        bookings = Booking.objects.all()
        serializer = BookingSerializer(bookings, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = BookingSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def create_booking(request):
    if request.method == 'POST':
        serializer = BookingSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class BookingDetailView(APIView):
    def get_object(self, pk):
        try:
            return Booking.objects.get(pk=pk)
        except Booking.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

    def get(self, request, pk):
        booking = self.get_object(pk)
        serializer = BookingSerializer(booking)
        return Response(serializer.data)

    def put(self, request, pk):
        booking = self.get_object(pk)
        serializer = BookingSerializer(booking, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        booking = self.get_object(pk)
        booking.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Bus
from .serializers import BusSerializer

class BusList(APIView):
    def get(self, request):
        buses = Bus.objects.all()
        serializer = BusSerializer(buses, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = BusSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class BusDetail(APIView):
    def get_object(self, pk):
        try:
            return Bus.objects.get(pk=pk)
        except Bus.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

    def get(self, request, pk):
        bus = self.get_object(pk)
        serializer = BusSerializer(bus)
        return Response(serializer.data)

    def put(self, request, pk):
        bus = self.get_object(pk)
        serializer = BusSerializer(bus, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        bus = self.get_object(pk)
        bus.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from.models import Expenditure
from.serializers import ExpenditureSerializer

class ExpenditureList(APIView):
    def get(self, request):
        expenditures = Expenditure.objects.all()
        serializer = ExpenditureSerializer(expenditures, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = ExpenditureSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ExpenditureDetail(APIView):
    def get_object(self, pk):
        try:
            return Expenditure.objects.get(pk=pk)
        except Expenditure.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

    def get(self, request, pk):
        expenditure = self.get_object(pk)
        serializer = ExpenditureSerializer(expenditure)
        return Response(serializer.data)

    def put(self, request, pk):
        expenditure = self.get_object(pk)
        serializer = ExpenditureSerializer(expenditure, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        expenditure = self.get_object(pk)
        expenditure.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
from rest_framework import generics
from .models import Route
from .serializers import RouteSerializer

class RouteListCreate(generics.ListCreateAPIView):
    queryset = Route.objects.all()
    serializer_class = RouteSerializer

class RouteRetrieveUpdateDestroy(generics.RetrieveUpdateDestroyAPIView):
    queryset = Route.objects.all()
    serializer_class = RouteSerializer


from rest_framework import generics
from .models import CustomUser
from .serializers import CustomUserSerializer
from .permissions import IsAdminUser

class AdminOnlyView(generics.ListCreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [IsAdminUser]


from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .models import Contact

@csrf_exempt
def contact(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        message = request.POST.get('message')
        contact = Contact(name=name, email=email, message=message)
        contact.save()
        return JsonResponse({'message': 'Form submitted successfully!'})
    return JsonResponse({'message': 'Invalid request method.'})


from .models import Contact
from .serializers import ContactSerializer

class ContactCreateView(APIView):
    def post(self, request):
        serializer = ContactSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Contact form submitted successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ContactListView(APIView):
    def get(self, request):
        contacts = Contact.objects.all()
        serializer = ContactSerializer(contacts, many=True)
        return Response(serializer.data)