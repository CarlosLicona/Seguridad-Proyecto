"""
URL configuration for proyectofinal project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
import proyectofinal.views as vistas
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', vistas.login),
    path('login', vistas.login),
    path('registro', vistas.registrar_servicio),
    path('usuarios', vistas.registrar_usuario),
    path('monitoreo', vistas.monitoreo_admin),
    path('servidor', vistas.monitoreo),
    path('buscar_servicios', vistas.buscar_servicios),
    path('registrar_estado', vistas.registrar_estado),
    path('leer_estados', vistas.leer_estados),
    path('control_estados', vistas.control_estados),
    path('logout', vistas.logout_view),
    path('token', vistas.login_token),
    path('mensaje_telegram', vistas.enviar_token),
    path('eliminar_token', vistas.eliminar_token),
    path('eliminar_User', vistas.eliminnar_usuario),
    path('eliminar_Ser', vistas.eliminar_servidor),
    path('actualizar_User', vistas.modificar_usuario),
    path('actualizar_Ser', vistas.modificar_servicio),
    path('relacion', vistas.relacion),
]

urlpatterns += staticfiles_urlpatterns()
