# Generated by Django 5.1.7 on 2025-03-20 14:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0010_remove_orderitem_updated_at_order_updated_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='complete_address',
            field=models.TextField(blank=True, null=True),
        ),
    ]
