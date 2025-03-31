from django.contrib import admin
from .models import Category, Product, StockItem, InventoryTransaction

# Register your models here.

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'parent', 'created_at', 'updated_at')
    list_filter = ('parent',)
    search_fields = ('name', 'description')
    readonly_fields = ('created_at', 'updated_at')

@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ('name', 'sku', 'category', 'price', 'is_active', 'created_at')
    list_filter = ('category', 'is_active')
    search_fields = ('name', 'sku', 'barcode', 'description')
    readonly_fields = ('created_at', 'updated_at')

@admin.register(StockItem)
class StockItemAdmin(admin.ModelAdmin):
    list_display = ('product', 'quantity', 'location', 'batch_number', 'expiry_date', 'created_at')
    list_filter = ('location', 'expiry_date')
    search_fields = ('product__name', 'product__sku', 'batch_number', 'location')
    readonly_fields = ('created_at', 'updated_at')

@admin.register(InventoryTransaction)
class InventoryTransactionAdmin(admin.ModelAdmin):
    list_display = ('product', 'transaction_type', 'quantity', 'reference', 'created_at')
    list_filter = ('transaction_type', 'created_at')
    search_fields = ('product__name', 'product__sku', 'reference', 'notes')
    readonly_fields = ('created_at', 'updated_at')
