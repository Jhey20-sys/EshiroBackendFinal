# Generated by Django 5.1.7 on 2025-03-20 12:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0008_remove_user_payment_method_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='order',
            name='status',
            field=models.CharField(choices=[('pending', 'Pending'), ('processing', 'Processing'), ('completed', 'Completed'), ('cancelled', 'Cancelled')], default='pending', max_length=20),
        ),
        migrations.AddField(
            model_name='orderitem',
            name='updated_at',
            field=models.DateTimeField(auto_now=True),
        ),
        migrations.AlterField(
            model_name='profile',
            name='complete_address',
            field=models.TextField(blank=True),
        ),
        migrations.AlterField(
            model_name='profile',
            name='payment_method',
            field=models.CharField(blank=True, max_length=50),
        ),
    ]
