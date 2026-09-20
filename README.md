# Sistema HTML Seguro con Google Apps Script

Este paquete permite administrar prácticas HTML con una interfaz simple de clics.

## Roles

- **ADMINISTRADOR**: crea usuarios, carga HTML, elimina apps, activa/desactiva, programa horarios y ve informes.
- **DOCENTE**: activa/desactiva apps, programa horarios y ve informes.
- **ESTUDIANTE**: ingresa a prácticas autorizadas y genera/consulta sus propios informes.

## Archivos principales

- `apps_script/Code.gs`: backend para Google Apps Script.
- `apps_script/Index.html`: interfaz web completa.
- `apps_script/appsscript.json`: configuración del proyecto.
- `html_para_subir/`: incluye las dos prácticas HTML de ejemplo que puedes cargar desde el panel.
- `documentacion/Tutorial_Sistema_HTML_Seguro.pdf`: tutorial paso a paso en formato Beamer.

## Resumen de instalación

1. Crear una hoja de cálculo nueva en Google Sheets.
2. Ir a **Extensiones > Apps Script**.
3. Copiar `Code.gs` e `Index.html` en el proyecto.
4. En configuración del proyecto, activar `appsscript.json` y pegar el contenido proporcionado.
5. Ejecutar `doGet` o desplegar como aplicación web para autorizar permisos.
6. Desplegar como Web App: ejecutar como **yo** y acceso **cualquier persona con el enlace**.
7. Abrir la URL del despliegue.
8. Crear el primer usuario ADMINISTRADOR.
9. Cargar los HTML desde el panel.
10. Crear docentes y estudiantes.

## Seguridad incluida

- Login con contrasena.
- Roles verificados en servidor.
- Activacion/desactivacion central.
- Horarios de apertura/cierre.
- Sesiones temporales.
- Apps almacenadas en Drive, entregadas solo tras autorizacion.
- Bloqueo disuasorio de clic derecho y atajos comunes.
- Bloqueo de ejecucion local del HTML servido.
- Aviso de propiedad intelectual e IA inyectado en cada practica.
- Auditoria e informes.

## Limitacion honesta

Ningun sistema web puede impedir absolutamente que un usuario autorizado haga captura de pantalla o transcriba una pregunta. La proteccion real consiste en no publicar libremente el banco completo, verificar permisos en servidor y evitar que copias locales funcionen en condiciones normales.
