# Generated by Django 5.1.6 on 2025-03-11 02:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0005_profile_cellphone_number_profile_complete_address_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='profile',
            name='email',
            field=models.EmailField(null = True, max_length=254, unique=True),
            preserve_default=False,
        ),
    ]
