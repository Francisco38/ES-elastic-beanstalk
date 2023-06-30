from django.urls import path

from . import views

urlpatterns = [
    path("", views.login),
    path("login", views.login),
    path("prescription/<int:prescription_id>", views.prescription),
    path("prescription/payment/<int:prescription_id>", views.payment),
    path("orders", views.orders),
    path("confirmOrder/<int:orderId>", views.orderConfirm),
]
