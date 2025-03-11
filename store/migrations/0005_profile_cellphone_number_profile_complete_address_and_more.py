# Generated by Django 5.1.6 on 2025-03-11 02:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0004_alter_user_payment_method'),
    ]

    operations = [
        migrations.AddField(
            model_name='profile',
            name='cellphone_number',
            field=models.CharField(blank=True, max_length=15, null=True, unique=True),
        ),
        migrations.AddField(
            model_name='profile',
            name='complete_address',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='profile',
            name='full_name',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
