# SafePass Vault

## Descripción general

**SafePass Vault** es una aplicación web diseñada para centralizar y proteger usuarios, contraseñas, claves API y tokens en una bóveda cifrada. Resuelve el problema de almacenar credenciales en texto plano o en archivos dispersos, ofreciendo a estudiantes y usuarios personales una interfaz para clasificar, buscar, crear, revelar temporalmente y exportar credenciales.

La aplicación deriva una clave mediante **PBKDF2-SHA-256**, cifra los datos con **AES-256-GCM** y utiliza **HMAC-SHA-256** para verificar la integridad de los respaldos. Las claves de cifrado se mantienen temporalmente en memoria y pueden eliminarse al bloquear la bóveda.

## Tecnologías y librerías utilizadas

- **HTML5** para la estructura de la interfaz.
- **CSS3** para el diseño responsivo, las tarjetas y el tema visual.
- **JavaScript** para la lógica de interfaz, búsqueda, filtrado y cifrado.
- **Web Crypto API** para PBKDF2, AES-256-GCM y HMAC-SHA-256.
- **JSON** para los metadatos y los respaldos cifrados.
- **Next.js 16**, **React 19** y **TypeScript** están disponibles como entorno opcional de desarrollo; no hacen falta para abrir la bóveda en Chrome.
- **Tailwind CSS 4** y componentes compatibles con shadcn para recursos visuales adicionales.
- **Vercel Analytics** para analítica opcional en producción.
- **pnpm** como gestor de paquetes.

## Estructura del repositorio

- [`public/index.html`](public/index.html): página principal y estructura visual de la bóveda.
- [`public/css/styles.css`](public/css/styles.css): estilos responsivos, tema visual y componentes de interfaz.
- [`public/js/app.js`](public/js/app.js): carga de datos, búsqueda, filtros, generador, cifrado, desbloqueo, exportación e importación.
- [`public/data/vault.json`](public/data/vault.json): copia de referencia de la configuración; la página incluye la configuración necesaria para abrirse como archivo local.
- [`next.config.mjs`](next.config.mjs): configuración de Next.js, rewrite de la ruta principal y encabezados HTTP de seguridad.
- [`app/layout.tsx`](app/layout.tsx): diseño raíz de Next.js y configuración básica de metadatos.
- [`app/globals.css`](app/globals.css): recursos globales de Tailwind CSS y estilos base.
- [`components/ui/button.tsx`](components/ui/button.tsx): componente reutilizable de botón.
- [`package.json`](package.json): dependencias y comandos de ejecución del proyecto.
- [`pnpm-lock.yaml`](pnpm-lock.yaml): versiones exactas resueltas por pnpm.
- [`tsconfig.json`](tsconfig.json): configuración de TypeScript.

## Ejecución en Chrome sin dependencias

No necesitas instalar Node.js, pnpm ni paquetes, ni iniciar un servidor:

1. Abre Google Chrome.
2. Pulsa **Ctrl+O** y selecciona `public/index.html` dentro de la carpeta del proyecto.

Mantén las carpetas `css` y `js` junto a `index.html` dentro de `public`. La configuración inicial está incluida en la página, así que Chrome no necesita cargar el archivo JSON por separado. Las credenciales añadidas se mantienen en memoria; exporta un backup cifrado para conservarlas y luego impórtalo cuando quieras recuperarlas.

### Desarrollo opcional con Next.js

Si quieres ejecutar o desplegar el entorno Next.js, sí necesitarás Node.js, Corepack y las dependencias del proyecto:

```bash
corepack enable
pnpm install
pnpm dev
```

Después abre `http://localhost:3000`. No es necesario configurar variables de entorno ni ejecutar una base de datos. Para comprobar una compilación de producción local:

```bash
pnpm build
pnpm start
```

La bóveda usa Web Crypto API, disponible en versiones actuales de Chrome al abrir archivos locales y también en `localhost` o sitios HTTPS.

### Despliegue en la nube

El proyecto está preparado para desplegarse en **Vercel**:

1. Sube el repositorio a GitHub, GitLab o Bitbucket.
2. Importa el proyecto desde el panel de Vercel.
3. Selecciona **Next.js** como framework; Vercel detectará el comando de construcción.
4. Usa `pnpm install` como instalación y `pnpm build` como compilación si necesitas configurarlos manualmente.
5. Despliega el proyecto. La ruta `/` se redirige internamente a `public/index.html`.

## Guía rápida de uso

1. Abre SafePass Vault en el navegador.
2. Pulsa **Abrir mi Bóveda** o **Desbloquear bóveda**.
3. En el primer uso, crea una Llave Maestra con al menos 8 caracteres.
4. Selecciona una categoría o utiliza el buscador para filtrar credenciales por servicio, URL o usuario.
5. Pulsa **Nueva credencial** y completa servicio, URL, usuario, categoría y contraseña.
6. Ajusta la longitud del generador y activa mayúsculas, minúsculas, números o símbolos si deseas crear una contraseña automáticamente.
7. Guarda la credencial mediante **Guardar y cifrar**.
8. Usa los botones de cada fila para revelar temporalmente la contraseña, copiar el usuario o la contraseña, o eliminar el registro.
9. Utiliza **Exportar backup** para descargar el respaldo cifrado con extensión `.enc`.
10. Utiliza **Importar backup**, selecciona el archivo exportado e introduce su Llave Maestra para verificar la integridad y restaurar las credenciales.
11. Pulsa **Bloquear bóveda** al terminar. Esta acción elimina las claves activas de memoria y vuelve a ocultar las contraseñas.
