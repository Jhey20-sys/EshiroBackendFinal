from django.contrib import admin
from .models import Product, User, Order, Cart, Wishlist, Payment, Profile  

class OrderAdmin(admin.ModelAdmin):
    def save_model(self, request, obj, form, change):
        if not obj.pk:  # Check if the object has a primary key
            obj.save()  # Save the order first before assigning related items


admin.site.register(Product)
admin.site.register(User)  
admin.site.register(Order)
admin.site.register(Cart)
admin.site.register(Wishlist)
admin.site.register(Payment)
admin.site.register(Profile)