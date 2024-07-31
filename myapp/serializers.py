from rest_framework import serializers
from .models import CustomUser, Bus, Route, Booking, BusReview, BusExpenditure
from django.contrib.auth.forms import PasswordResetForm


class CustomUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'password', 'role']

    def create(self, validated_data):
        role = validated_data.get('role', 'default_role')
        user = CustomUser.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            role=role
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

    def update(self, instance, validated_data):
        instance.username = validated_data.get('username', instance.username)
        instance.email = validated_data.get('email', instance.email)
        instance.role = validated_data.get('role', instance.role)
        if 'password' in validated_data:
            instance.set_password(validated_data['password'])
        instance.save()
        return instance
from django.contrib.auth import authenticate

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, data):
        email = data.get("email")
        password = data.get("password")
        
        if email and password:
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                raise serializers.ValidationError("Invalid email or password.")
            
            if user.check_password(password):
                if user.is_active:
                    data["user"] = user
                else:
                    raise serializers.ValidationError("User is deactivated.")
            else:
                raise serializers.ValidationError("Invalid email or password.")
        else:
            raise serializers.ValidationError("Must provide both email and password.")
        return data
    
class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        self.reset_form = PasswordResetForm(data=self.initial_data)
        if not self.reset_form.is_valid():
            raise serializers.ValidationError(('Error validating email'))
        return value

    def save(self):
        request = self.context.get('request')
        self.reset_form.save(
            use_https=request.is_secure(),
            email_template_name='registration/password_reset_email.html',
            request=request,
        )

class BusSerializer(serializers.ModelSerializer):
    class Meta:
        model = Bus
        fields = '__all__'

class RouteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Route
        fields = '__all__'

class BookingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Booking
        fields = [
            'booking_id', 'booking_date', 'booking_time', 'booking_route', 
            'booking_bus', 'booking_passenger', 'booking_fare', 'booking_payment', 
            'booking_confirmation', 'booking_email'
        ]

    def create(self, validated_data):
        booking = Booking.objects.create(**validated_data)
        return booking

    def update(self, instance, validated_data):
        instance.booking_date = validated_data.get('booking_date', instance.booking_date)
        instance.booking_time = validated_data.get('booking_time', instance.booking_time)
        instance.booking_route = validated_data.get('booking_route', instance.booking_route)
        instance.booking_bus = validated_data.get('booking_bus', instance.booking_bus)
        instance.booking_passenger = validated_data.get('booking_passenger', instance.booking_passenger)
        instance.booking_fare = validated_data.get('booking_fare', instance.booking_fare)
        instance.booking_payment = validated_data.get('booking_payment', instance.booking_payment)
        instance.booking_confirmation = validated_data.get('booking_confirmation', instance.booking_confirmation)
        instance.booking_email = validated_data.get('booking_email', instance.booking_email)
        instance.save()
        return instance

class BusReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusReview
        fields = ['review_text', 'review_user', 'review_bus', 'review_date']

class BusExpenditureSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusExpenditure
        fields = '__all__'

class BusReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusReview
        fields = '__all__'

from.models import Expenditure

class ExpenditureSerializer(serializers.ModelSerializer):
    class Meta:
        model = Expenditure
        fields = '__all__'


from rest_framework import serializers
from .models import Contact

class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = ['id', 'name', 'email', 'message']