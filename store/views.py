from rest_framework.exceptions import ValidationError
from rest_framework import viewsets, generics, status, permissions
from django.contrib.auth import get_user_model, logout
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from .models import Product, Order, Profile, Cart, Wishlist, Payment
from .serializers import (ProductSerializer, UserSerializer, RegisterSerializer, OrderSerializer, CartSerializer, WishlistSerializer, PaymentSerializer, OrderItemSerializer, ProfileSerializer)
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import api_view, permission_classes
from .models import Cart, OrderItem
from .serializers import CartSerializer
from rest_framework import serializers
from django.db import transaction
from rest_framework.generics import RetrieveAPIView

User = get_user_model()

@api_view(["GET", "DELETE"])
@permission_classes([IsAuthenticated])
def cart_view(request, pk=None):
    if request.method == "GET":
        cart_items = Cart.objects.filter(user=request.user)
        serializer = CartSerializer(cart_items, many=True)
        return Response(serializer.data)

    elif request.method == "DELETE":
        try:
            item = Cart.objects.get(id=pk, user=request.user)
            item.delete()
            return Response({"message": "Item removed successfully"}, status=204)
        except Cart.DoesNotExist:
            return Response({"error": "Item not found"}, status=404)

@api_view(['GET'])
@permission_classes([IsAuthenticated])  # Ensure authentication is required
def get_cart(request):
    user = request.user
    cart_items = Cart.objects.filter(user=user)
    serializer = CartSerializer(cart_items, many=True)
    return Response(serializer.data)

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_order(request):
    product_ids = request.data.get("product_ids", [])
    quantities = request.data.get("quantities", [])

    if not product_ids or not quantities:
        return Response({"error": "Product IDs and Quantities are required."}, status=400)
    if len(product_ids) != len(quantities):
        return Response({"error": "Product IDs and Quantities lists must have the same length."}, status=400)

    total_price = 0

    with transaction.atomic():
        # Create the order
        order = Order.objects.create(user=request.user)
        print(f"Order created: {order.id}")

        # Create order items and calculate total price
        for product_id, quantity in zip(product_ids, quantities):
            try:
                product = Product.objects.get(id=product_id)
            except Product.DoesNotExist:
                return Response({"error": f"Product with ID {product_id} not found."}, status=404)

            print(f"Product ID: {product.id}, Price: {product.price}, Quantity: {quantity}")
            item_total_price = product.price * quantity
            total_price += item_total_price

            # Create OrderItem
            OrderItem.objects.create(
                order=order,
                product=product,
                quantity=quantity,
                total_price=item_total_price,  # Make sure this field is being set correctly
            )

        # Update the total price in the order
        print(f"Total price for the order: {total_price}")
        order.total_price = total_price
        order.save()

    return Response({"id": order.id, "total_price": order.total_price}, status=201)



class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing users.
    - Admins can list, retrieve, update, and delete users.
    - Regular users can only view & update their own profile.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get_permissions(self):
        """ Define permissions dynamically based on action. """
        if self.action in ["list", "destroy"]:
            return [IsAdminUser()]  # Only admins can list or delete users
        return [IsAuthenticated()]  # Other actions require authentication

    def list(self, request):
        """ List all users (Admin only) """
        if not request.user.is_staff:
            return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)

        users = User.objects.all()
        serializer = self.get_serializer(users, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        """ Retrieve a user. Admins can retrieve any, users can retrieve their own. """
        if pk == "me":
            user = request.user  # Allow users to get their own profile using /users/me/
        else:
            user = get_object_or_404(User, pk=pk)

            if not request.user.is_staff and user != request.user:
                return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.get_serializer(user)
        return Response(serializer.data)

    def update(self, request, pk=None):
        """ Allow users to update their own info, admins can update any. """
        if pk == "me":
            user = request.user
        else:
            user = get_object_or_404(User, pk=pk)
            if not request.user.is_staff and user != request.user:
                return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.get_serializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        """ Admins can delete users. Users cannot delete their own accounts. """
        user = get_object_or_404(User, pk=pk)
        if not request.user.is_staff:
            return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)

        user.delete()
        return Response({"message": "User deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

class UserDetailView(APIView):
    def get(self, request, id):
        try:
            user = User.objects.get(id=id)
            return Response({"id": user.id, "username": user.username, "email": user.email})
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=404)

class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    authentication_classes = []
    permission_classes = [AllowAny]

# Register & Login
class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        user = serializer.save()
        user.is_active = True  # Ensure users are active upon registration
        user.save()

class LoginView(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            "email": user.email,
            "token": token.key,  # ✅ Return Token
            "user_id": user.id,  # ✅ Include user_id
        })

# Profile & Logout
class ProfileView(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user
class ProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = ProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        """Retrieve the profile of the authenticated user"""
        return self.request.user.profile  # This should return the Profile instance

    def put(self, request, *args, **kwargs):
        """Handle updating user profile"""
        profile = self.get_object()  # Directly retrieve Profile instance

        serializer = self.get_serializer(profile, data=request.data, partial=True)  # Allow partial updates
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if hasattr(request.user, 'auth_token'):
            request.user.auth_token.delete()
        logout(request)
        return Response({"message": "User logged out successfully"}, status=200)


# CART VIEW SET
class CartViewSet(viewsets.ModelViewSet):
    serializer_class = CartSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Cart.objects.filter(user=self.request.user)

    def create(self, request, *args, **kwargs):
        product = get_object_or_404(Product, id=request.data.get("product_id"))
        cart_item, created = Cart.objects.get_or_create(user=request.user, product=product)

        if not created:
            if product.stock > cart_item.quantity:
                cart_item.quantity += 1
                cart_item.save()
            else:
                return Response({"error": "Not enough stock"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "Product added to cart"}, status=status.HTTP_201_CREATED)

    def destroy(self, request, *args, **kwargs):
        cart_item = get_object_or_404(Cart, user=request.user, id=kwargs["pk"])
        cart_item.delete()
        return Response({"message": "Product removed from cart"}, status=status.HTTP_204_NO_CONTENT)

    def update(self, request, *args, **kwargs):
        """Update the quantity of an item in the cart."""
        cart_item = get_object_or_404(Cart, user=request.user, id=kwargs["pk"])
        new_quantity = request.data.get("quantity")

        if not isinstance(new_quantity, int) or new_quantity <= 0:
            return Response({"error": "Quantity must be a positive integer"}, status=status.HTTP_400_BAD_REQUEST)

        cart_item.quantity = new_quantity
        cart_item.save()
        
        return Response({"message": "Cart item updated successfully", "quantity": cart_item.quantity}, status=status.HTTP_200_OK)

# Cart View (Fetch all items in the cart)
class CartView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Fetch the cart items for the authenticated user."""
        cart_items = Cart.objects.filter(user=request.user)

        if not cart_items.exists():
            return Response({"message": "Your cart is empty"}, status=status.HTTP_200_OK)

        serializer = CartSerializer(cart_items, many=True, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        """Add a product to the cart for the authenticated user."""
        product_id = request.data.get("product_id")
        quantity = request.data.get("quantity", 1)

        if not product_id:
            return Response({"error": "Product ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        if not isinstance(quantity, int) or quantity <= 0:
            return Response({"error": "Quantity must be a positive integer"}, status=status.HTTP_400_BAD_REQUEST)

        product = get_object_or_404(Product, id=product_id)

        # Check if the item already exists in the cart
        cart_item, created = Cart.objects.get_or_create(user=request.user, product=product)
        if not created:
            cart_item.quantity += quantity  # Increase quantity if item exists
        else:
            cart_item.quantity = quantity
        cart_item.save()

        return Response(
            {"message": "Product added to cart successfully", "cart_item_id": cart_item.id},
            status=status.HTTP_201_CREATED
        )

# Cart Add View (Separate post method for adding items)
class CartAddView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        product_id = request.data.get("product_id")
        quantity = request.data.get("quantity", 1)

        try:
            product = Product.objects.get(id=product_id)

            # Check if the item is already in the cart
            cart_item, created = Cart.objects.get_or_create(user=request.user, product=product)
            if not created:
                cart_item.quantity += quantity
                cart_item.save()

            return Response({"message": "Product added to cart"}, status=201)

        except Product.DoesNotExist:
            return Response({"error": "Product not found"}, status=404)

# Cart Clear View (Clear all items in the cart for the authenticated user)
class CartClearView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Clear the cart for the authenticated user."""
        print("Clearing cart for user:", request.user.id)  # Log to check if the request hits this endpoint
        cart_items = Cart.objects.filter(user=request.user)

        if cart_items.exists():
            cart_items.delete()
            return Response({"message": "Cart cleared successfully"}, status=status.HTTP_200_OK)
        else:
            return Response({"message": "Your cart is already empty"}, status=status.HTTP_200_OK)
### Payments
class PaymentViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        payments = Payment.objects.filter(user=request.user)
        serializer = PaymentSerializer(payments, many=True)
        return Response(serializer.data)

    def create(self, request):
        order_id = request.data.get("order_id")
        amount = request.data.get("amount")

        if not order_id or not amount:
            return Response({"error": "order_id and amount are required"}, status=status.HTTP_400_BAD_REQUEST)

        payment = Payment.objects.create(
            user=request.user,
            order_id=order_id,
            amount=amount,
            status="completed",
            transaction_id=f"TXN{order_id}"
        )

        return Response({"message": "Payment successful", "payment_id": payment.id}, status=status.HTTP_201_CREATED)

    def retrieve(self, request, pk=None):
        payment = get_object_or_404(Payment, id=pk, user=request.user)
        serializer = PaymentSerializer(payment)
        return Response(serializer.data)

    def refund(self, request, pk=None):
        payment = get_object_or_404(Payment, id=pk, user=request.user)

        if payment.status != "completed":
            return Response({"error": "Only completed payments can be refunded"}, status=status.HTTP_400_BAD_REQUEST)

        payment.status = "refunded"
        payment.save()
        return Response({"message": "Refund successful", "payment_id": payment.id}, status=status.HTTP_200_OK)

class ProductView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        product = Product.objects.all()
        serializer = ProductSerializer(product, many=True)
        return Response(serializer.data)
    
# Wishlist ViewSet
class WishlistViewSet(viewsets.ModelViewSet):
    serializer_class = WishlistSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Retrieve the wishlist items for the authenticated user."""
        return Wishlist.objects.filter(user=self.request.user)

    def create(self, request, *args, **kwargs):
        """Add a product to the wishlist."""
        print(request.data)  # Add this line to check the request data
        product_id = request.data.get("product")
        if not product_id:
            return Response({"error": "Product ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        product = get_object_or_404(Product, id=product_id)

        # Check if the product already exists in the wishlist
        wishlist_item, created = Wishlist.objects.get_or_create(user=request.user, product=product)

        if created:
            return Response({"message": "Product added to wishlist"}, status=status.HTTP_201_CREATED)
        return Response({"message": "Product is already in the wishlist"}, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        """Remove a product from the wishlist."""
        wishlist_item = get_object_or_404(Wishlist, user=request.user, id=kwargs["pk"])
        wishlist_item.delete()
        return Response({"message": "Product removed from wishlist"}, status=status.HTTP_204_NO_CONTENT)


class CartView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Fetch the cart items for the authenticated user."""
        cart_items = Cart.objects.filter(user=request.user)

        if not cart_items.exists():
            return Response({"message": "Your cart is empty"}, status=status.HTTP_200_OK)

        serializer = CartSerializer(cart_items, many=True, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        """Add a product to the cart for the authenticated user."""
        product_id = request.data.get("product_id")
        quantity = request.data.get("quantity", 1)

        if not product_id:
            return Response({"error": "Product ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        if not isinstance(quantity, int) or quantity <= 0:
            return Response({"error": "Quantity must be a positive integer"}, status=status.HTTP_400_BAD_REQUEST)

        product = get_object_or_404(Product, id=product_id)

        # Check if the item already exists in the cart
        cart_item, created = Cart.objects.get_or_create(user=request.user, product=product)
        if not created:
            cart_item.quantity += quantity  # Increase quantity if item exists
        else:
            cart_item.quantity = quantity
        cart_item.save()

        return Response(
            {"message": "Product added to cart successfully", "cart_item_id": cart_item.id},
            status=status.HTTP_201_CREATED
        )

################### ORDER COMPONENTS ####################
class CreateOrderAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        cart_items = Cart.objects.filter(user=user)

        if not cart_items.exists():
            return Response({"error": "No items in the cart"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                # ✅ Calculate total price from cart items
                total_price = sum(cart.product.price * cart.quantity for cart in cart_items)

                # ✅ Create order
                order = Order.objects.create(user=user, total_price=total_price)

                # ✅ Move cart items to OrderItem
                order_items = [
                    OrderItem(
                        order=order,
                        product=cart.product,
                        quantity=cart.quantity,
                        total_price=cart.product.price * cart.quantity,
                    )
                    for cart in cart_items
                ]
                OrderItem.objects.bulk_create(order_items)  # ✅ Bulk insert for efficiency

                # ✅ Clear the cart after order is placed
                cart_items.delete()

            return Response(
                {"message": "Order created successfully", "order_id": order.id},
                status=status.HTTP_201_CREATED
            )

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
# ✅ ORDER VIEWSET (Handles All CRUD Operations)
class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        user = self.request.user

        # Ensure the user is authenticated
        if not user.is_authenticated:
            raise ValidationError({"error": "User must be authenticated."})

        # Allow the frontend to send the total_price
        total_price = self.request.data.get('total_price', 0)

        # Ensure `total_price` is provided and is a positive value
        if total_price <= 0:
            raise ValidationError({"error": "Total price must be greater than zero."})

        # Create the order with the user and the provided total price
        order = serializer.save(user=user, total_price=total_price)

        # If you still want to clear the cart after creating the order (optional), you can keep this part
        # carts = Cart.objects.filter(user=user)
        # carts.delete()

    def perform_update(self, serializer):
        instance = serializer.save()

        # Ensure the updated total price is valid
        if instance.total_price <= 0:
            raise ValidationError({"error": "Total price cannot be zero or negative."})
        
class OrderCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        product_ids = request.data.get("product_ids", [])  # List of product IDs
        quantities = request.data.get("quantities", [])    # List of quantities corresponding to products
        total_price = request.data.get("total_price", 0)  # Get total_price from frontend

        if total_price <= 0:
            raise ValidationError({"error": "Total price must be greater than zero."})

        # Validate products and quantities
        for product_id, quantity in zip(product_ids, quantities):
            try:
                product = Product.objects.get(id=product_id)
            except Product.DoesNotExist:
                return Response({"error": f"Product with ID {product_id} not found."}, status=404)

            if quantity <= 0:
                return Response({"error": f"Quantity for product {product_id} must be greater than zero."}, status=400)

        with transaction.atomic():
            # ✅ Create order with the provided total_price
            order = Order.objects.create(user=user, total_price=total_price)

            # ✅ Create order items for each product
            for product_id, quantity in zip(product_ids, quantities):
                try:
                    product = Product.objects.get(id=product_id)
                except Product.DoesNotExist:
                    return Response({"error": f"Product with ID {product_id} not found."}, status=404)

                item_total_price = product.price * quantity
                OrderItem.objects.create(
                    order=order,
                    product=product,
                    quantity=quantity,
                    total_price=item_total_price,  # Store item total price
                )

        return Response({"id": order.id, "message": "Order created successfully."}, status=201)

# ✅ PLACE ORDER FROM CART (Alternative to `OrderCreateView`)
class PlaceOrderView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        cart_items = Cart.objects.filter(user=user)

        if not cart_items.exists():
            return Response({"error": "No items in the cart."}, status=400)

        # Get total_price from frontend (sent in the request)
        total_price = request.data.get("total_price", 0)

        if total_price <= 0:
            raise ValidationError({"error": "Total price must be greater than zero."})

        with transaction.atomic():
            # ✅ Create order with the provided total_price
            order = Order.objects.create(user=user, total_price=total_price)

            # ✅ Create order items for each product in the cart
            for cart in cart_items:
                item_total_price = cart.product.price * cart.quantity
                OrderItem.objects.create(
                    order=order,
                    product=cart.product,
                    quantity=cart.quantity,
                    total_price=item_total_price,
                )

            # ✅ Clear cart after order placement
            cart_items.delete()

        return Response({"id": order.id, "message": "Order placed successfully."}, status=201)
    
# ✅ ORDER DETAIL VIEW (Retrieve Order Details)
class OrderDetailView(APIView):
    permission_classes = [IsAuthenticated]
    queryset = Order.objects.all()
    serializer_class = OrderSerializer

    def get(self, request, order_id):
        try:
            order = Order.objects.get(id=order_id, user=request.user)
            return Response(OrderSerializer(order).data, status=200)
        except Order.DoesNotExist:
            return Response({"error": "Order not found."}, status=404)
    
    def get_serializer_context(self):
        return {"request": self.request}


 ################ ORDER ITEM ####################################   

@api_view(['GET'])
def get_order_items(request, order_id):
    """
    Retrieve all items in an order.
    """
    print(f"Received order_id: {order_id}")  # Debugging

    if not order_id:
        return Response({'error': 'Order ID is required.'}, status=400)

    try:
        items = OrderItem.objects.filter(order_id=order_id)
        if not items.exists():
            return Response({'error': 'No order items found for this order.'}, status=404)

        serializer = OrderItemSerializer(items, many=True)
        return Response(serializer.data)
    except Exception as e:
        print(f"Error fetching order items: {e}")  # Log error to console
        return Response({'error': 'Failed to retrieve order items.'}, status=500)



class OrderItemListView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        order_id = request.data.get("order_id")
        product_id = request.data.get("product_id")
        quantity = request.data.get("quantity", 1)

        if not order_id or not product_id:
            return Response({"error": "Order ID and Product ID are required."}, status=400)

        if not isinstance(quantity, int) or quantity <= 0:
            return Response({"error": "Quantity must be a positive integer."}, status=400)

        try:
            order = Order.objects.get(id=order_id, user=request.user)
        except Order.DoesNotExist:
            return Response({"error": "Order not found or does not belong to the user."}, status=404)

        try:
            product = Product.objects.get(id=product_id)
        except Product.DoesNotExist:
            return Response({"error": "Product not found."}, status=404)

        # Log the order and product info
        print(f"Order: {order}, Product: {product}, Quantity: {quantity}")

        total_price = product.price * quantity

        try:
            with transaction.atomic():
                order_item = OrderItem.objects.create(
                    order=order,
                    product=product,
                    quantity=quantity,
                    price=total_price,
                )

                order.total_price += total_price
                order.save()

            return Response(
                {
                    "success": "Order item created successfully.",
                    "order_item_id": order_item.id,
                    "total_price": total_price,
                },
                status=201,
            )
        except Exception as e:
            print("Error:", e)  # Log any exception that happens
            return Response({"error": "Failed to create order item."}, status=500)

class CreateOrderItemView(APIView):
    def post(self, request):
        serializer = OrderItemSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(["GET"])
def search_products(request):
    query = request.GET.get("q", "").strip().lower()
    
    if not query:
        return Response([])  # Return empty list if no query

    products = Product.objects.filter(name__icontains=query)  # Case-insensitive search
    serializer = ProductSerializer(products, many=True)
    return Response(serializer.data)

@api_view(["GET"])
def product_detail(request, product_id):
    try:
        product = Product.objects.get(id=product_id)
        serializer = ProductSerializer(product)
        return Response(serializer.data)
    except Product.DoesNotExist:
        return Response({"error": "Product not found"}, status=404)
    
def product_detail_by_name(request, product_name):
    product = get_object_or_404(Product, name__iexact=product_name)  # Case-insensitive search
    return JsonResponse({
        "id": product.id,
        "name": product.name,
        "description": product.description,
        "price": product.price,
    })