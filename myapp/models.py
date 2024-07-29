from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser
from django.core.mail import send_mail



STATUS_CHOICES = [
    ('pending', 'Pending'),
    ('confirmed', 'Confirmed'),
    ('cancelled', 'Cancelled'),
]

STATUS_PAYMENT = [
    ('paid', 'Paid'),
    ('pending', 'Pending'),
]

class CustomUser(AbstractUser):
    ROLE_CHOICES = (
        ('superadmin', 'Super Admin'),
        ('admin', 'Admin'),
        ('staff', 'Staff'),
        ('user', 'User'),
    )

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='user')
    

class Bus(models.Model):
    bus_id = models.CharField(max_length=50, unique=True)
    bus_manufacture = models.CharField(max_length=200)
    bus_price = models.IntegerField(default=0) 
    bus_reg = models.CharField(max_length=50)
    bus_capacity = models.CharField(max_length=10, default=0)
    bus_owner = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='owned_buses')
    bus_owner_contact = models.CharField(max_length=50)
    bus_owner_identification = models.IntegerField(max_length=254)
    bus_driver = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='driven_buses')
    bus_driver_contact = models.CharField(max_length=50)
    bus_driver_identification = models.IntegerField(max_length=254)
    bus_conductor = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='conducted_buses')
    bus_conductor_contact = models.CharField(max_length=50)
    bus_conductor_identification = models.IntegerField(max_length=254)
    date_purchased = models.DateTimeField(default=timezone.now)
    registered_date = models.DateTimeField(auto_now=True)
    bus_insurance = models.CharField(max_length=50)

    def __str__(self):
        return f"Bus ID: {self.bus_id}, Registration: {self.bus_reg}, Owner: {self.bus_owner.username}, Driver: {self.bus_driver.username}, Conductor: {self.bus_conductor.username}"
    
class BusExpenditure(models.Model):
    bus = models.ForeignKey(Bus, on_delete=models.CASCADE, related_name='expenditures')
    monthly_fuel_cost = models.DecimalField(max_digits=10, decimal_places=2)
    insurance_cost = models.DecimalField(max_digits=10, decimal_places=2)
    sacco_payment = models.DecimalField(max_digits=10, decimal_places=2)
    owner_payment = models.DecimalField(max_digits=10, decimal_places=2)
    driver_payment = models.DecimalField(max_digits=10, decimal_places=2)
    conductor_payment = models.DecimalField(max_digits=10, decimal_places=2)
    service_cost = models.DecimalField(max_digits=10, decimal_places=2)
    service_date = models.DateField()
    last_tyre_replacement = models.DateField()
    next_inspection_date = models.DateField()

    def __str__(self):
        return f"Expenditure for Bus ID: {self.bus.bus_id}"

class Route(models.Model):
    route_id = models.CharField(max_length=50, unique=True)
    route_name = models.CharField(max_length=50, unique=True)
    route_destination1 = models.CharField(max_length=50, unique=True)
    route_destination2 = models.CharField(max_length=50, unique=True)
    route_destination3 = models.CharField(max_length=50, unique=True)
    route_destination4 = models.CharField(max_length=50, unique=True)
    route_fare = models.CharField(max_length=50, unique=True)
    route_bus1 = models.ForeignKey('Bus', on_delete=models.CASCADE, related_name='route1')
    route_bus2 = models.ForeignKey('Bus', on_delete=models.CASCADE, related_name='route2')
    route_bus3 = models.ForeignKey('Bus', on_delete=models.CASCADE, related_name='route3')

    def __str__(self):
        return f"Route ID: {self.route_id}, Name: {self.route_name}, Fare: {self.route_fare}"
    

class Booking(models.Model):
    booking_id = models.AutoField(primary_key=True)
    booking_date = models.DateField()
    booking_time = models.TimeField()
    booking_route = models.CharField(max_length=255)
    booking_bus = models.CharField(max_length=255)
    booking_seat = models.CharField(max_length=255)
    booking_passenger = models.CharField(max_length=255)
    booking_status = models.CharField(max_length=255) 
    booking_fare = models.DecimalField(max_digits=10, decimal_places=2)
    booking_payment = models.CharField(max_length=255, choices=STATUS_PAYMENT, blank=True, null=True)
    booking_confirmation = models.CharField(max_length=255, choices=STATUS_CHOICES, blank=True, null=True)

    def __str__(self):
        return f"Booking ID: {self.booking_id}, Route: {self.booking_route.route_name}, Passenger: {self.booking_passenger.username}, Status: {self.booking_status}"
    

class BusReview(models.Model):
    review_text = models.TextField()
    review_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='reviews')
    review_bus = models.ForeignKey(Bus, on_delete=models.CASCADE, related_name='reviews')
    review_date = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Review for Bus ID: {self.review_bus.bus_id}, Reviewer: {self.review_user.username}, Date: {self.review_date}"
    

class Expenditure(models.Model):
    monthly_fuel_cost = models.DecimalField(max_digits=10, decimal_places=2)
    insurance_cost = models.DecimalField(max_digits=10, decimal_places=2)
    sacco_payment = models.DecimalField(max_digits=10, decimal_places=2)
    owner_payment = models.DecimalField(max_digits=10, decimal_places=2)
    driver_payment = models.DecimalField(max_digits=10, decimal_places=2)
    conductor_payment = models.DecimalField(max_digits=10, decimal_places=2)
    service_cost = models.DecimalField(max_digits=10, decimal_places=2)
    service_date = models.DateField()
    last_tyre_replacement = models.DateField()
    next_inspection_date = models.DateField()

    def __str__(self):
        return f"Expenditure for Bus ID: {self.bus.bus_id}"

class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    message = models.TextField()

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        send_mail(
            'New Contact Form Submission',
            f'Name: {self.name}\nEmail: {self.email}\nMessage: {self.message}',
            '',  
            ['roygacherumuhungi@gmail.com'],
            fail_silently=False,
        )


