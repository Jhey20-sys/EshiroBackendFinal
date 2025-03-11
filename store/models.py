from django.db import models
from django.utils.timezone import now
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings

# User Manager
class UserManager(BaseUserManager):
    def create_customer(self, email, full_name=None, cellphone_number=None, complete_address=None, password=None):
        if not email:
            raise ValueError("Email address is required.")
        
        email = self.normalize_email(email)
        user = self.model(
            email=email,
            full_name=full_name,
            cellphone_number=cellphone_number,
            complete_address=complete_address,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, full_name, cellphone_number, complete_address, password):
        user = self.create_customer(
            email=email,
            full_name=full_name,
            cellphone_number=cellphone_number,
            complete_address=complete_address,
            password=password
        )
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


# Custom User Model
class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=255, blank=True, null=True)
    complete_address = models.TextField(blank=True, null=True)
    cellphone_number = models.CharField(max_length=15, unique=True, blank=True, null=True)
    image_url = models.URLField(max_length=200, blank=True, null=True)
    
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name', 'cellphone_number', 'complete_address']

    def __str__(self):
        return self.email


# Profile Model
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    reset_password_token = models.CharField(max_length=255, blank=True, null=True)
    reset_password_token_expiry = models.DateTimeField(blank=True, null=True)
    email = models.EmailField(unique=True, blank = True, null = True)
    full_name = models.CharField(max_length=255, blank=True, null=True)
    complete_address = models.TextField(blank=True)
    cellphone_number = models.CharField(max_length=15, unique=True, blank=True)
    payment_method = models.CharField(max_length=50, blank=True)
    def __str__(self):
        return self.user.email


@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)
    else:
        instance.profile.save()
        
# Product Model [GOODS]
class Product(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(default="No description available")
    price = models.DecimalField(max_digits=10, decimal_places=2)
    stock = models.PositiveIntegerField(default=0)
    image_url = models.URLField(max_length=500, blank=True, null=True)
    product_size = models.CharField(max_length=50, blank=True, null=True)
    created_at = models.DateTimeField(default=now)

    def __str__(self):
        return self.name


# Cart Model [GOODS]
class Cart(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="cart")
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name="cart_items", null=True)
    quantity = models.PositiveIntegerField(default=1)
    added_at = models.DateTimeField(auto_now_add=True)

    def subtotal(self):
        return self.quantity * self.product.price

    def __str__(self):
        return f"{self.user.email} - {self.product.name} ({self.quantity})"


# Order Model
class Order(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="orders")
    total_price = models.DecimalField(max_digits=10, decimal_places=2, default=0)  
    created_at = models.DateTimeField(auto_now_add=True, null=True)

    def save(self, *args, **kwargs):
        # Ensure that total_price is set from the frontend when creating the order
        if not self.pk:  # If order is new (no primary key)
            super().save(*args, **kwargs)  # Save first to get an ID
        super().save(update_fields=["total_price"])  # Save only total_price field

    def __str__(self):
        return f"Order {self.id} - {self.user.email}"


# OrderItem Model
class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="order_items")
    product = models.ForeignKey(Product, on_delete=models.SET_NULL, null=True, blank=True)
    quantity = models.PositiveIntegerField(default=1)
    price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)  # Store price per unit

    def save(self, *args, **kwargs):
        """Ensure price per unit is set before saving."""
        if not self.price and self.product:
            self.price = self.product.price  # ✅ Store price per unit, not total
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.product.name if self.product else 'Unknown Product'} - Quantity: {self.quantity}"



# Wishlist Model
class Wishlist(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="wishlist")
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name="wishlist_items")
    added_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email} - {self.product.name}"


# Payment Model
class Payment(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_COMPLETED = 'completed'
    STATUS_FAILED = 'failed'
    STATUS_REFUNDED = 'refunded'

    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_COMPLETED, 'Completed'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_REFUNDED, 'Refunded'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="payments")
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="payments", null=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=STATUS_PENDING)
    mode_of_payment = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(default=now)

    def __str__(self):
        return f"Payment {self.id} - {self.status} ({self.amount})"
