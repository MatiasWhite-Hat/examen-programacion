const XON_API_URL = "https://api.xposedornot.com/v1/breach-analytics";
const OPENPHISH_FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt";
const INTERNETDB_API_URL = "https://internetdb.shodan.io";
const PWNED_PASSWORDS_API_URL = "https://api.pwnedpasswords.com/range";

// Guardan los resultados para poder mostrarlos y filtrarlos.
let brechasActuales = [];
let openPhishFeed = null;
let openPhishFeedFetchedAt = 0;

// Espera a que cargue la página y conecta formularios y botones.
document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("formCorreo").addEventListener("submit", event => {
        event.preventDefault();
        consultarCorreo();
    });
    document.getElementById("inputFiltro").addEventListener("input", filtrarBrechas);
    document.getElementById("formOpenPhish").addEventListener("submit", event => {
        event.preventDefault();
        consultarOpenPhish();
    });
    document.getElementById("formInternetDB").addEventListener("submit", event => {
        event.preventDefault();
        consultarInternetDB();
    });
    document.getElementById("formPwnedPasswords").addEventListener("submit", event => {
        event.preventDefault();
        consultarPwnedPasswords();
    });
    document.getElementById("navModuloBrechas").addEventListener("click", () => cambiarModulo("brechas"));
    document.getElementById("navModuloOpenPhish").addEventListener("click", () => cambiarModulo("openphish"));
    document.getElementById("navModuloInternetDB").addEventListener("click", () => cambiarModulo("internetdb"));
    document.getElementById("navModuloPwnedPasswords").addEventListener("click", () => cambiarModulo("pwnedpasswords"));
});

// Busca y muestra las brechas asociadas a un correo.
async function consultarCorreo() {
    const input = document.getElementById("inputCorreo");
    const correo = input.value.trim();
    if (!correo || !input.validity.valid) {
        mostrarEstadoBrechas("Ingresa una dirección de correo válida.", "danger");
        input.focus();
        return;
    }

    // Esconde los resultados anteriores mientras llega la nueva respuesta.
    mostrarCargaBrechas(true);
    document.getElementById("mensajeEstado").style.display = "none";
    document.getElementById("tablaBrechas").style.display = "none";
    document.getElementById("seccionMetricas").style.display = "none";

    try {
        const url = `${XON_API_URL}?email=${encodeURIComponent(correo)}`;
        const respuesta = await fetch(url);
        const data = await respuesta.json();

        if (respuesta.status === 404 || obtenerCampo(data, ["error"]) === "Not found") {
            procesarBrechas([]);
            mostrarEstadoBrechas("No se encontraron brechas para este correo.", "success");
            return;
        }
        if (!respuesta.ok) {
            throw new Error(`XposedOrNot respondió con HTTP ${respuesta.status}.`);
        }

        const detalles = obtenerCampo(data, ["ExposedBreaches", "exposedBreaches"]);
        const lista = obtenerCampo(detalles, ["breaches_details", "breachesDetails"]);
        if (!Array.isArray(lista)) {
            const campos = detalles && typeof detalles === "object" ? Object.keys(detalles).join(", ") : "sin detalles";
            throw new Error(`Formato de respuesta inesperado (ExposedBreaches: ${campos}).`);
        }

        procesarBrechas(lista);
        if (lista.length === 0) {
            mostrarEstadoBrechas("No se encontraron brechas para este correo.", "success");
        }
    } catch (error) {
        mostrarEstadoBrechas(`No se pudo consultar XposedOrNot: ${obtenerMensajeError(error)}`, "danger");
    } finally {
        mostrarCargaBrechas(false);
    }
}

// Prepara la lista de brechas y actualiza la tabla y sus números.
function procesarBrechas(lista) {
    brechasActuales = [];
    for (const elemento of lista) {
        if (typeof elemento === "string") {
            brechasActuales.push({ breach: elemento });
        } else if (elemento && typeof elemento === "object") {
            brechasActuales.push(elemento);
        } else {
            brechasActuales.push({});
        }
    }

    document.getElementById("inputFiltro").disabled = brechasActuales.length === 0;
    document.getElementById("inputFiltro").value = "";
    actualizarMetricas();
    dibujarBrechas(brechasActuales);
    if (brechasActuales.length > 0) {
        document.getElementById("tablaBrechas").style.display = "table";
        document.getElementById("seccionMetricas").style.display = "grid";
        document.getElementById("mensajeEstado").style.display = "none";
    }
}

// Muestra solo las brechas que contienen lo escrito en el filtro.
function filtrarBrechas() {
    const termino = document.getElementById("inputFiltro").value.trim().toLowerCase();
    const filtradas = [];

    for (const brecha of brechasActuales) {
        const campos = [
            obtenerCampo(brecha, ["breach", "breachID", "name", "domain"]),
            obtenerCampo(brecha, ["industry"]),
            obtenerCampo(brecha, ["xposed_data", "exposedData"]),
            obtenerCampo(brecha, ["details", "exposureDescription"])
        ];
        let texto = "";

        for (const campo of campos) {
            texto += " " + (Array.isArray(campo) ? campo.join(" ") : String(campo || ""));
        }

        if (texto.toLowerCase().includes(termino)) {
            filtradas.push(brecha);
        }
    }

    if (filtradas.length === 0) {
        const tbody = document.getElementById("tbodyBrechas");
        tbody.replaceChildren(crearFilaVacia("No hay resultados para ese filtro."));
    } else {
        dibujarBrechas(filtradas);
    }
    document.getElementById("tablaBrechas").style.display = "table";
}

// Crea una fila de la tabla por cada brecha recibida.
function dibujarBrechas(lista) {
    const tbody = document.getElementById("tbodyBrechas");
    tbody.replaceChildren();
    if (lista.length === 0) {
        tbody.appendChild(crearFilaVacia("No se encontraron brechas."));
        return;
    }

    for (const brecha of lista) {
        const fila = document.createElement("tr");
        agregarCelda(fila, obtenerCampo(brecha, ["breach", "breachID", "name", "domain"]) || "Desconocido", "strong");
        agregarCelda(fila, obtenerCampo(brecha, ["xposed_date", "breachedDate", "addedDate", "date"]) || "N/D");
        agregarCelda(fila, obtenerCampo(brecha, ["industry"]) || "General");
        const expuestos = obtenerCampo(brecha, ["xposed_data", "exposedData"]);
        agregarCelda(fila, Array.isArray(expuestos) ? expuestos.join(", ") : expuestos || "No especificados");
        tbody.appendChild(fila);
    }
}

// Cuenta las brechas y las industrias distintas.
function actualizarMetricas() {
    const industrias = new Set();
    for (const brecha of brechasActuales) {
        const industria = obtenerCampo(brecha, ["industry"]);
        if (industria) industrias.add(industria);
    }
    document.getElementById("statTotal").textContent = String(brechasActuales.length);
    document.getElementById("statIndustrias").textContent = String(industrias.size);
}

// Descarga el feed de OpenPhish y compara el dominio ingresado.
async function consultarOpenPhish() {
    const input = document.getElementById("inputValorOpenPhish");
    const valor = input.value.trim();
    if (!valor) {
        mostrarEstadoOpenPhish("Ingresa una URL para comprobar.", "warning");
        input.focus();
        return;
    }

    const valorUrl = validarUrl(valor);
    if (!valorUrl) {
        mostrarEstadoOpenPhish("La URL debe comenzar con http:// o https://.", "warning");
        input.focus();
        return;
    }

    // Compara el dominio ingresado con las direcciones del feed.
    valorUrl.hash = "";
    mostrarCargaOpenPhish(true);
    document.getElementById("resultadoOpenPhish").style.display = "none";
    document.getElementById("mensajeOpenPhish").style.display = "none";
    try {
        const feed = await obtenerFeedOpenPhish();
        const coincidencias = [];
        for (const urlFeed of feed) {
            try {
                if (new URL(urlFeed).hostname === valorUrl.hostname) {
                    coincidencias.push(urlFeed);
                }
            } catch {
                continue;
            }
        }
        mostrarResultadoOpenPhish(coincidencias, valorUrl.hostname);
    } catch (error) {
        mostrarEstadoOpenPhish(`No se pudo consultar el feed de OpenPhish: ${obtenerMensajeError(error)}`, "danger");
    } finally {
        mostrarCargaOpenPhish(false);
    }
}

// Usa el feed guardado por cinco minutos; si venció, lo descarga de nuevo.
async function obtenerFeedOpenPhish() {
    const cacheVigente = Date.now() - openPhishFeedFetchedAt < 5 * 60 * 1000;
    if (openPhishFeed && cacheVigente) {
        return openPhishFeed;
    }

    const controlador = new AbortController();
    const timeout = setTimeout(() => controlador.abort(), 15000);
    let texto;
    try {
        const respuesta = await fetch(OPENPHISH_FEED_URL, {
            cache: "no-cache",
            signal: controlador.signal
        });
        if (!respuesta.ok) {
            throw new Error(`OpenPhish respondió con HTTP ${respuesta.status}.`);
        }
        texto = await respuesta.text();
    } catch (error) {
        if (error instanceof Error && error.name === "AbortError") {
            throw new Error("La descarga del feed tardó demasiado. Intenta nuevamente.");
        }
        throw error;
    } finally {
        clearTimeout(timeout);
    }

    const feed = [];
    for (const linea of texto.split(/\r?\n/)) {
        const url = linea.trim();
        if (/^https?:\/\//i.test(url)) {
            feed.push(url);
        }
    }
    if (feed.length === 0) {
        throw new Error("OpenPhish devolvió un feed vacío o con formato inesperado.");
    }

    openPhishFeed = feed;
    openPhishFeedFetchedAt = Date.now();
    return openPhishFeed;
}

// Muestra el módulo elegido y actualiza el estado visual del menú.
function cambiarModulo(modulo) {
    const vistaBrechas = modulo === "brechas";
    const vistaOpenPhish = modulo === "openphish";
    const vistaInternetDB = modulo === "internetdb";
    const vistaPwnedPasswords = modulo === "pwnedpasswords";

    document.getElementById("vistaModuloBrechas").style.display = vistaBrechas ? "block" : "none";
    document.getElementById("vistaModuloOpenPhish").style.display = vistaOpenPhish ? "block" : "none";
    document.getElementById("vistaModuloInternetDB").style.display = vistaInternetDB ? "block" : "none";
    document.getElementById("vistaModuloPwnedPasswords").style.display = vistaPwnedPasswords ? "block" : "none";

    actualizarBotonModulo("navModuloBrechas", vistaBrechas);
    actualizarBotonModulo("navModuloOpenPhish", vistaOpenPhish);
    actualizarBotonModulo("navModuloInternetDB", vistaInternetDB);
    actualizarBotonModulo("navModuloPwnedPasswords", vistaPwnedPasswords);
}

// Marca en el menú cuál módulo está abierto.
function actualizarBotonModulo(id, activo) {
    const boton = document.getElementById(id);
    boton.classList.toggle("active", activo);
    boton.setAttribute("aria-pressed", activo);
    if (activo) {
        boton.setAttribute("aria-current", "page");
    } else {
        boton.removeAttribute("aria-current");
    }
}

// Comprueba la contraseña con el método de rango de Pwned Passwords.
// Solo se envían los primeros cinco caracteres del hash, no la contraseña.
async function consultarPwnedPasswords() {
    const input = document.getElementById("inputContrasenaPwned");
    const contrasena = input.value;
    if (!contrasena) {
        mostrarEstadoPwnedPasswords("Ingresa una contraseña para comprobar.", "warning");
        input.focus();
        return;
    }
    if (!window.crypto || !window.crypto.subtle) {
        mostrarEstadoPwnedPasswords("Este navegador no permite calcular SHA-1 de forma segura. Abre la página en HTTPS o en localhost e inténtalo nuevamente.", "danger");
        return;
    }

    mostrarCargaPwnedPasswords(true);
    document.getElementById("resultadoPwnedPasswords").style.display = "none";
    document.getElementById("mensajePwnedPasswords").style.display = "none";
    try {
        // Compara el resto del hash con la respuesta del servicio.
        const hash = await calcularSha1(contrasena);
        const prefijo = hash.slice(0, 5);
        const sufijo = hash.slice(5);
        const controlador = new AbortController();
        const timeout = setTimeout(() => controlador.abort(), 15000);
        let respuesta;
        try {
            respuesta = await fetch(`${PWNED_PASSWORDS_API_URL}/${prefijo}`, {
                cache: "no-store",
                headers: {
                    Accept: "text/plain",
                    "Add-Padding": "true"
                },
                signal: controlador.signal
            });
        } finally {
            clearTimeout(timeout);
        }

        if (!respuesta.ok) {
            throw new Error(`Pwned Passwords respondió con HTTP ${respuesta.status}.`);
        }
        const texto = await respuesta.text();
        const coincidencias = texto.split(/\r?\n/);
        let coincidencia = 0;
        for (const linea of coincidencias) {
            const registro = linea.trim();
            if (!registro) continue;
            if (!/^[0-9a-f]{35}:\d+$/i.test(registro)) {
                throw new Error("Pwned Passwords devolvió una respuesta con formato inesperado.");
            }
            const partes = registro.split(":");
            if (partes[0].toUpperCase() === sufijo) {
                coincidencia = Number(partes[1]);
                break;
            }
        }
        mostrarResultadoPwnedPasswords(coincidencia);
    } catch (error) {
        if (error instanceof Error && error.name === "AbortError") {
            mostrarEstadoPwnedPasswords("La consulta tardó demasiado. Intenta nuevamente.", "danger");
        } else if (error instanceof TypeError) {
            mostrarEstadoPwnedPasswords("No se pudo conectar. Revisa la conexión o si el navegador bloqueó la petición (CORS).", "danger");
        } else {
            mostrarEstadoPwnedPasswords(`No se pudo consultar Pwned Passwords: ${obtenerMensajeError(error)}`, "danger");
        }
    } finally {
        mostrarCargaPwnedPasswords(false);
    }
}

// Convierte la contraseña en una huella para buscarla sin enviarla.
async function calcularSha1(texto) {
    const bytes = new TextEncoder().encode(texto);
    const hash = await crypto.subtle.digest("SHA-1", bytes);
    const bytesHash = new Uint8Array(hash);
    let resultado = "";
    for (const byte of bytesHash) {
        resultado += byte.toString(16).padStart(2, "0");
    }
    return resultado.toUpperCase();
}

// Muestra si la contraseña apareció en los registros consultados.
function mostrarResultadoPwnedPasswords(cantidad) {
    const resultado = document.getElementById("resultadoPwnedPasswords");
    resultado.className = `pwned-result rounded border ${cantidad > 0 ? "pwned-result-exposed" : "pwned-result-unmatched"}`;
    resultado.textContent = cantidad > 0
        ? `Esta contraseña apareció ${cantidad.toLocaleString("es-CL")} veces en filtraciones conocidas. Cámbiala y evita reutilizarla.`
        : "No se encontró esta contraseña en los registros consultados. Esto no garantiza que sea segura.";
    resultado.style.display = "block";
    document.getElementById("mensajePwnedPasswords").style.display = "none";
}

// Muestra un aviso y esconde el resultado anterior.
function mostrarEstadoPwnedPasswords(mensaje, tipo) {
    const estado = document.getElementById("mensajePwnedPasswords");
    estado.textContent = mensaje;
    estado.className = `text-center py-5 rounded border border-secondary border-opacity-25 ${tipo === "danger" ? "text-danger" : "text-warning"}`;
    estado.style.display = "block";
    document.getElementById("resultadoPwnedPasswords").style.display = "none";
}

// Activa o desactiva el indicador de carga y el botón.
function mostrarCargaPwnedPasswords(cargando) {
    document.getElementById("loadingPwnedPasswords").style.display = cargando ? "block" : "none";
    document.getElementById("btnConsultarPwnedPasswords").disabled = cargando;
}

// Busca información pública de una dirección IP en InternetDB.
async function consultarInternetDB() {
    const input = document.getElementById("inputIPInternetDB");
    const ip = input.value.trim().replace(/^\[|\]$/g, "");
    input.value = ip;

    if (!validarDireccionIP(ip)) {
        mostrarEstadoInternetDB("Ingresa una dirección IPv4 o IPv6 válida.", "warning");
        input.focus();
        return;
    }

    // Consulta Shodan y muestra un mensaje si algo falla.
    mostrarCargaInternetDB(true);
    document.getElementById("resultadoInternetDB").style.display = "none";
    document.getElementById("mensajeInternetDB").style.display = "none";

    const controlador = new AbortController();
    const timeout = setTimeout(() => controlador.abort(), 15000);
    try {
        const respuesta = await fetch(`${INTERNETDB_API_URL}/${encodeURIComponent(ip)}`, {
            signal: controlador.signal,
            headers: { Accept: "application/json" }
        });
        const textoRespuesta = await respuesta.text();
        let data;
        try {
            data = textoRespuesta ? JSON.parse(textoRespuesta) : {};
        } catch {
            throw new Error("Shodan devolvió una respuesta que no es JSON.");
        }

        if (respuesta.status === 404) {
            mostrarEstadoInternetDB("InternetDB no tiene información indexada para esa IP; las IP privadas o reservadas pueden no aparecer. Esto no significa que la IP sea segura.", "warning");
            return;
        }
        if (!respuesta.ok) {
            const detalle = (data && (data.detail || data.error)) || `Shodan respondió con HTTP ${respuesta.status}.`;
            throw new Error(String(detalle));
        }
        if (!data || typeof data !== "object" || Array.isArray(data) || !data.ip) {
            throw new Error("La respuesta de Shodan no contiene una IP reconocible.");
        }

        mostrarResultadoInternetDB(data);
    } catch (error) {
        if (error instanceof Error && error.name === "AbortError") {
            mostrarEstadoInternetDB("La consulta tardó demasiado. Intenta nuevamente.", "danger");
        } else if (error instanceof TypeError) {
            mostrarEstadoInternetDB("No se pudo conectar. Revisa la conexión o si el navegador bloqueó la petición (CORS).", "danger");
        } else {
            mostrarEstadoInternetDB(`No se pudo consultar InternetDB: ${obtenerMensajeError(error)}`, "danger");
        }
    } finally {
        clearTimeout(timeout);
        mostrarCargaInternetDB(false);
    }
}

// Revisa que la dirección tenga un formato válido de IPv4 o IPv6.
function validarDireccionIP(ip) {
    const partesIPv4 = ip.split(".");
    if (partesIPv4.length === 4 && partesIPv4.every(parte =>
        /^\d{1,3}$/.test(parte) &&
        (parte.length === 1 || parte[0] !== "0") &&
        Number(parte) <= 255
    )) {
        return true;
    }
    try {
        const direccion = new URL(`http://[${ip}]/`);
        return direccion.hostname.startsWith("[") && direccion.hostname.endsWith("]");
    } catch {
        return false;
    }
}

// Arma el resultado de Shodan con sus datos principales.
function mostrarResultadoInternetDB(data) {
    const contenedor = document.getElementById("resultadoInternetDB");
    contenedor.replaceChildren();
    agregarDetalleInternetDB(contenedor, "IP consultada", data.ip);
    agregarListaInternetDB(contenedor, "Puertos abiertos", data.ports, valor => `Puerto ${valor}`, "No se encontraron puertos listados.");
    agregarListaInternetDB(contenedor, "Nombres de host", data.hostnames, valor => valor, "Sin nombres de host registrados.");
    agregarListaInternetDB(contenedor, "Etiquetas", data.tags, valor => valor, "Sin etiquetas.");
    agregarListaInternetDB(contenedor, "CPEs / productos detectados", data.cpes, valor => valor, "Sin CPEs registrados.");
    agregarListaInternetDB(contenedor, "Vulnerabilidades", data.vulns, valor => valor, "Sin vulnerabilidades listadas por InternetDB.");
    contenedor.style.display = "block";
    document.getElementById("mensajeInternetDB").style.display = "none";
}

// Agrega un dato sencillo, como la IP, a los resultados.
function agregarDetalleInternetDB(contenedor, titulo, valor) {
    const parrafo = document.createElement("p");
    parrafo.className = "mb-3";
    const etiqueta = document.createElement("strong");
    etiqueta.textContent = `${titulo}: `;
    parrafo.append(etiqueta, document.createTextNode(String(valor)));
    contenedor.appendChild(parrafo);
}

// Agrega una lista de datos o un aviso si no hay datos.
function agregarListaInternetDB(contenedor, titulo, valores, formatear, mensajeVacio) {
    const seccion = document.createElement("div");
    seccion.className = "mb-3";
    const encabezado = document.createElement("h6");
    encabezado.className = "text-info";
    encabezado.textContent = titulo;
    seccion.appendChild(encabezado);

    if (!Array.isArray(valores) || valores.length === 0) {
        const vacio = document.createElement("p");
        vacio.className = "text-muted small mb-0";
        vacio.textContent = mensajeVacio;
        seccion.appendChild(vacio);
    } else {
        const lista = document.createElement("ul");
        lista.className = "mb-0";
        for (const valor of valores) {
            const elemento = document.createElement("li");
            const texto = formatear(String(valor));
            if (titulo === "Vulnerabilidades" && /^CVE-\d{4}-\d+$/i.test(texto)) {
                const enlace = document.createElement("a");
                enlace.href = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(texto)}`;
                enlace.target = "_blank";
                enlace.rel = "noopener noreferrer";
                enlace.textContent = texto;
                elemento.appendChild(enlace);
            } else {
                elemento.textContent = texto;
            }
            lista.appendChild(elemento);
        }
        seccion.appendChild(lista);
    }
    contenedor.appendChild(seccion);
}

// Muestra un aviso en el módulo de Shodan.
function mostrarEstadoInternetDB(mensaje, tipo) {
    const estado = document.getElementById("mensajeInternetDB");
    estado.textContent = mensaje;
    estado.className = `text-center py-5 rounded border border-secondary border-opacity-25 ${tipo === "danger" ? "text-danger" : "text-warning"}`;
    estado.style.display = "block";
}

// Muestra u oculta la carga de Shodan.
function mostrarCargaInternetDB(cargando) {
    document.getElementById("loadingInternetDB").style.display = cargando ? "block" : "none";
    document.getElementById("btnConsultarInternetDB").disabled = cargando;
}

// Muestra si el dominio aparece en el feed de OpenPhish.
function mostrarResultadoOpenPhish(matches, hostname) {
    const contenedor = document.getElementById("resultadoOpenPhish");
    contenedor.replaceChildren();

    const estado = document.createElement("p");
    estado.className = "mb-2";
    const texto = document.createElement("strong");
    if (matches.length === 0) {
        texto.textContent = "El dominio no aparece en el feed comunitario de OpenPhish.";
        estado.append(texto, document.createTextNode(" Esto no garantiza que esté libre de phishing."));
    } else {
        texto.textContent = "El dominio aparece en el feed comunitario de phishing:";
        estado.append(texto, document.createTextNode(` ${hostname}`));
    }
    contenedor.appendChild(estado);

    if (matches.length > 0) {
        const lista = document.createElement("ul");
        lista.className = "mb-0";
        for (const match of matches.slice(0, 5)) {
            const elemento = document.createElement("li");
            elemento.textContent = match;
            lista.appendChild(elemento);
        }
        if (matches.length > 5) {
            const mas = document.createElement("li");
            mas.textContent = `y ${matches.length - 5} URL(s) más de este dominio`;
            lista.appendChild(mas);
        }
        contenedor.appendChild(lista);
    }

    contenedor.style.display = "block";
}

// Muestra un aviso en el módulo de brechas.
function mostrarEstadoBrechas(mensaje, tipo) {
    const estado = document.getElementById("mensajeEstado");
    estado.textContent = mensaje;
    estado.className = `text-center py-5 rounded border border-secondary border-opacity-25 ${tipo === "danger" ? "text-danger" : tipo === "success" ? "text-success" : "text-warning"}`;
    estado.style.display = "block";
}

// Muestra un aviso en el módulo de OpenPhish.
function mostrarEstadoOpenPhish(mensaje, tipo) {
    const estado = document.getElementById("mensajeOpenPhish");
    estado.textContent = mensaje;
    estado.className = `text-center py-5 rounded border border-secondary border-opacity-25 ${tipo === "danger" ? "text-danger" : "text-warning"}`;
    estado.style.display = "block";
    document.getElementById("resultadoOpenPhish").style.display = "none";
}

// Muestra u oculta la carga de la consulta de brechas.
function mostrarCargaBrechas(cargando) {
    document.getElementById("loading").style.display = cargando ? "block" : "none";
    document.getElementById("btnConsultar").disabled = cargando;
}

// Muestra u oculta la carga de OpenPhish.
function mostrarCargaOpenPhish(cargando) {
    document.getElementById("loadingOpenPhish").style.display = cargando ? "block" : "none";
    document.getElementById("btnConsultarOpenPhish").disabled = cargando;
}

// Crea una fila con un mensaje cuando no hay resultados.
function crearFilaVacia(mensaje) {
    const fila = document.createElement("tr");
    const celda = document.createElement("td");
    celda.colSpan = 4;
    celda.className = "text-center text-muted py-4";
    celda.textContent = mensaje;
    fila.appendChild(celda);
    return fila;
}

// Agrega una celda de texto a una fila de la tabla.
function agregarCelda(fila, valor, etiqueta = "") {
    const celda = document.createElement("td");
    if (etiqueta) {
        const elemento = document.createElement(etiqueta);
        elemento.textContent = String(valor);
        celda.appendChild(elemento);
    } else {
        celda.textContent = String(valor);
    }
    fila.appendChild(celda);
}

// Busca un dato aunque el servicio lo entregue con mayúsculas distintas.
function obtenerCampo(objeto, nombres) {
    if (!objeto || typeof objeto !== "object") {
        return undefined;
    }

    for (const nombre of nombres) {
        for (const clave in objeto) {
            if (clave.toLowerCase() === nombre.toLowerCase()) {
                return objeto[clave];
            }
        }
    }
    return undefined;
}

// Acepta direcciones web que empiecen con http o https.
function validarUrl(valor) {
    try {
        const url = new URL(valor);
        return url.protocol === "http:" || url.protocol === "https:" ? url : undefined;
    } catch {
        return undefined;
    }
}

// Convierte distintos tipos de error en texto para mostrarlo.
function obtenerMensajeError(error) {
    return error instanceof Error ? error.message : String(error);
}