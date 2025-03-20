from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Product, Order, Cart, Wishlist, OrderItem, Payment, Profile
from rest_framework.authtoken.models import Token

User = get_user_model()

# User Serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'full_name', 'cellphone_number', 'complete_address']

class ProfileSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(source="user.email", read_only=True, required=False)
    full_name = serializers.CharField(source="user.full_name", required=False, allow_null=True)
    complete_address = serializers.CharField(source="user.complete_address", required=False, allow_null=True)
    cellphone_number = serializers.CharField(source="user.cellphone_number", required=False, allow_null=True)

    class Meta:
        model = Profile
        fields = ["email", "full_name", "complete_address", "cellphone_number", "payment_method"]

    def update(self, instance, validated_data):
        """Ensure both User and Profile are updated"""
        user_data = validated_data.pop("user", {})  # Extract nested user fields

        # Update Profile fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # Update User fields if provided
        user = instance.user
        for attr, value in user_data.items():
            setattr(user, attr, value)
        user.save()

        return instance
    
# Register Serializer
class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'full_name', 'cellphone_number', 'complete_address', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_customer(**validated_data)
        token, _ = Token.objects.get_or_create(user=user)  # ✅ Generate token on signup
        return user

# Login Serializer
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")
        user = User.objects.filter(email=email).first()

        if user and user.check_password(password):
            token, _ = Token.objects.get_or_create(user=user)  # ✅ Return token
            return {"email": user.email, "token": token.key}
        raise serializers.ValidationError("Invalid credentials")

# Product Serializer
class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = '__all__'

# Cart Serializer
class CartSerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(source="product.name", read_only=True)
    product_price = serializers.DecimalField(source="product.price", max_digits=10, decimal_places=2, read_only=True)
    product_image = serializers.CharField(source="product.image_url", read_only=True)
    product_id = serializers.IntegerField(source="product.id", read_only=True)  # ✅ Include product_id

    class Meta:
        model = Cart
        fields = ["id", "product_name", "product_price", "product_image", "quantity", "product_id"]  
    
# Wishlist Serializer
class WishlistSerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(source='product.name', read_only=True)
    product_price = serializers.DecimalField(source='product.price', max_digits=10, decimal_places=2, read_only=True)
    product_image = serializers.CharField(source="product.image_url", read_only=True)

    class Meta:
        model = Wishlist
        fields = ["id", "user", "product", "product_name", "product_price", "added_at", "product_image"]
        read_only_fields = ['user']


# Payment Serializer
class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = '__all__'
        read_only_fields = ['status', 'created_at', 'mode_of_payment']

###### ORDER SERIALIZER ##########

# ORDER ITEM SERIALIZER
class OrderItemSerializer(serializers.ModelSerializer):
    order_id = serializers.PrimaryKeyRelatedField(queryset=Order.objects.all(), source='order', write_only=True)
    product_id = serializers.PrimaryKeyRelatedField(queryset=Product.objects.all(), source='product', write_only=True)
    product_name = serializers.CharField(source='product.name', read_only=True)
    image = serializers.CharField(source='product.image_url', read_only=True)  # Use image_url instead

    class Meta:
        model = OrderItem
        fields = ['id', 'order_id', 'product_id', 'product_name', 'image', 'price', 'quantity']


# ORDER 
class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ['id', 'user', 'total_price', 'created_at']
        read_only_fields = ['created_at', 'user']  # Allow `total_price` input

    def create(self, validated_data):
        user = self.context['request'].user  

        if not user.is_authenticated:
            raise serializers.ValidationError({"user": ["Authentication required."]})

        # Ensure `total_price` is provided in the validated data
        total_price = validated_data.get("total_price", 0)

        # Create order with user and total price from frontend
        order = Order.objects.create(user=user, total_price=total_price)
        return order


# ORDER HISTORY
class OrderItemHistorySerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(source='product.name', read_only=True)
    product_image = serializers.URLField(source='product.image_url', read_only=True)
    
    class Meta:
        model = OrderItem
        fields = ['product_name', 'product_image', 'quantity', 'price']

class PaymentHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = ['mode_of_payment', 'status', 'created_at']

class OrderHistorySerializer(serializers.ModelSerializer):
    items = OrderItemHistorySerializer(source='order_items', many=True, read_only=True)
    payment_info = PaymentHistorySerializer(source='payments', many=True, read_only=True)
    
    class Meta:
        model = Order
        fields = ['id', 'total_price', 'status', 'updated_at', 'created_at', 'items', 'payment_info']