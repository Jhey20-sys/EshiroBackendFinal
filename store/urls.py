from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework.authtoken.views import obtain_auth_token  

from .views import (
    ProductViewSet, RegisterView, OrderViewSet, LogoutView, 
    CartViewSet, CartView, CartAddView, WishlistViewSet, PaymentViewSet, 
    UserViewSet, ProfileView, LoginView, OrderCreateView, 
    OrderDetailView, PlaceOrderView, CreateOrderAPIView, CartClearView,
    ProductView, get_order_items, OrderItemListView, CreateOrderItemView, UserDetailView,search_products, product_detail_by_name
)
from . import views

# API Router
router = DefaultRouter()
router.register(r'products', ProductViewSet, basename='product')
router.register(r'users', UserViewSet, basename='users')
router.register(r'orders', OrderViewSet, basename='order')
router.register(r'cart', CartViewSet, basename='cart')  
router.register(r'wishlist', WishlistViewSet, basename='wishlist')



# URL Patterns
urlpatterns = [
    path('', include(router.urls)),

    # User Authentication
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),  
    path('logout/', LogoutView.as_view(), name='logout'),
    
    # User Profile
    path('profile/', ProfileView.as_view(), name='profile'),
    path("user/<int:id>/", UserDetailView.as_view(), name="user-detail"),


    # Payments
    path("payments/", PaymentViewSet.as_view({"get": "list", "post": "create"}), name="payments"),
    path("payments/<int:pk>/", PaymentViewSet.as_view({"get": "retrieve"}), name="payment-detail"),
    path("payments/<int:pk>/refund/", PaymentViewSet.as_view({"post": "refund"}), name="payment-refund"),

    # Order Management
    path('orders/create/', OrderCreateView.as_view(), name='order-create'),
    path("orders/<int:id>/", OrderDetailView.as_view(), name="order-detail"),
    path('orders/', CreateOrderAPIView.as_view(), name='create-order'),
    path('place-order/', PlaceOrderView.as_view(), name='place-order'),

    # Order Items
    path('order-items/create/', CreateOrderItemView.as_view(), name="order-item-create"),  # For creating order items
    path('get-order-items/', get_order_items, name='get_order_items'),  # For fetching order items
    path('order-items/', OrderItemListView.as_view(), name='order-items-list'),
    path('order-items/<int:order_id>/', views.get_order_items, name='get-order-items'),
    path('order-items/<int:order_id>/', get_order_items, name='get_order_items'),

    # Cart management
    # path('cart/', CartView.as_view(), name='cart-view'),
    path('cart/add/', CartAddView.as_view(), name='cart-add'),
    path('carts/clear/', CartClearView.as_view(), name='cart-clear'),

    # Product
    path('products/', ProductView.as_view(), name='product-list'),
    path("search/", search_products, name="search_products"),  # Search API
    path("products/name/<str:product_name>/", product_detail_by_name, name="product_detail_by_name"),  # Search by product name
]
