# Generated by Django 5.0.6 on 2024-06-26 21:17

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0002_alter_customuser_options_alter_customuser_managers_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='bus',
            old_name='bus_conductor_email',
            new_name='bus_conductor_identification',
        ),
        migrations.RenameField(
            model_name='bus',
            old_name='bus_driver_email',
            new_name='bus_driver_identification',
        ),
        migrations.RenameField(
            model_name='bus',
            old_name='bus_owner_email',
            new_name='bus_owner_identification',
        ),
        migrations.AddField(
            model_name='bus',
            name='bus_capacity',
            field=models.CharField(default=0, max_length=10),
        ),
        migrations.AddField(
            model_name='bus',
            name='bus_price',
            field=models.IntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='bus',
            name='bus_conductor',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='conducted_buses', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='bus',
            name='bus_driver',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='driven_buses', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='bus',
            name='bus_owner',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='owned_buses', to=settings.AUTH_USER_MODEL),
        ),
        migrations.CreateModel(
            name='Booking',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('booking_id', models.CharField(max_length=50, unique=True)),
                ('booking_date', models.DateTimeField(default=django.utils.timezone.now)),
                ('booking_time', models.DateTimeField(default=django.utils.timezone.now)),
                ('booking_seat', models.CharField(max_length=50, unique=True)),
                ('booking_status', models.CharField(choices=[('pending', 'Pending'), ('confirmed', 'Confirmed'), ('cancelled', 'Cancelled')], default='pending', max_length=50)),
                ('booking_fare', models.CharField(max_length=50, unique=True)),
                ('booking_payment', models.CharField(choices=[('paid', 'Paid'), ('pending', 'Pending')], default='pending', max_length=50)),
                ('booking_cancel', models.BooleanField(default=False)),
                ('booking_bus', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='booking_bus', to='myapp.bus')),
                ('booking_passenger', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='booking', to=settings.AUTH_USER_MODEL)),
                ('booking_route', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='booking_route', to='myapp.route')),
            ],
        ),
    ]
