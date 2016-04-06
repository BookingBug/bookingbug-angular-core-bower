;window.bookingbug.translations.es = {
  ADDRESS: 'Dirección'
  AFTERNOON: 'Tarde'
  APPOINTMENT_REFERENCE: 'Información de la cita'
  AVAILABLE: 'Disponible'
  BACK: 'Regresar'
  BOOK: 'Cita'
  CALENDAR_PAGE_SUMMARY: 'Selecciona el día y la hora para tu {{service}} cita'
  CANCEL_BOOKING: 'Cancelar cita'
  CANCEL_CANCEL: 'No cancelar'
  CANCEL_CONFIRMATION: 'Tu cita ha sido cancelada.'
  CANCEL_QUESTION: 'Estás seguro que deseas cancelar tu cita'
  CATEGORY_PAGE_SUMMARY: 'Por favor, selecciona una Categoria de Servicio'
  CELL_PHONE: 'Teléfono celular'
  CLEAR_RESULTS: 'resultados claros'
  CONFIRM: 'Confirmar'
  CONFIRM_EMAIL: 'Confirmar correo electrónico'
  CONFIRM_EMAIL_ERROR: 'Dirección de correo electrónico no concuerda, por favor ingresa de nuevo '
  CONFIRMATION: 'Confirmación'
  CONFIRMATION_HEADING: 'Confirmación de cita'
  CONFIRMATION_HEADING_WAITLIST: 'Gracias {{name}}, las citas fueron calendarizadas exitosamente. Hemos enviado los detalles vía correo electrónico'
  CONFIRMATION_TEXT: 'Gracias {{name}}, tu cita ha sido confirmada. Hemos enviado los detalles vía correo electrónico'
  CONTINUE: 'Continuar'
  DATE: 'Fecha'
  DURATION: 'Duración'
  EMAIL: 'Correo electrónico'
  EMAIL_ERROR: 'Por favor ingresa una dirección  de correo electrónico válida'
  EXPORT: 'Exportar'
  EVENING: 'Noche'
  FIRST: 'primero'
  FIRST_NAME: 'Nombre'
  FIRST_NAME_ERROR: 'Por favor ingresa tu nombre'
  LAST: 'Último'
  LAST_NAME: 'Apellido'
  LAST_NAME_ERROR: 'Por favor ingresa tu apellido'
  MAP_PAGE_SUMMARY: 'Selecciona una sucursal para comenzar tu cita'
  MAP_MARKERS: '{{number}} Resultado de sucursales cercanas {{address}}'
  MAP_PLACEHOLDER: 'Ingresa una ciudad o código postal'
  MORNING: 'Mañana'
  MOVE_APPOINTMENT: 'Mover una cita'
  NAME: 'Nombre'
  NEW_CUSTOMER: 'Crear Nuevo cliente'
  NEXT: 'Siguiente'
  OTHER_INFORMATION: 'Otra información'
  PRICE: 'Precio'
  PHONE: 'Teléfono'
  PREVIOUS: 'Anterior'
  PRIMARY_PHONE_NUMBER: 'Número teléfono primario'
  PRIMARY_PHONE_NUMBER_ERROR: 'Por favor provee un número de teléfono o móvil'
  PRIVACY_POLICY: 'He leído y acepto <a href="#">Política de Privacidad</a> Oriental Bank'
  PRIVACY_POLICY_ERROR: 'Por favor, acepte nuestra política de privacidad para continuar'
  PRINT: 'Imprimir'
  PURCHASE_PAGE_SUMMARY: 'Tu cita'
  REVIEW: 'Revisar Cita'
  REQUIRED_FIELDS: '* Campos requeridos'
  REQUIRED_FIELD_ERROR: 'Este campo es requerido'
  SECONDARY_PHONE_NUMBER: 'Número de teléfono secundario'
  SECONDARY_PHONE_NUMBER_ERROR: 'Por favor provee un número de teléfono o móvil'
  SEARCH: 'Buscar'
  SEARCH_HEADING: 'Buscar cliente o crear nuevo cliente'
  SEARCH_PLACEHOLDER: 'buscar email o nombre'
  SELECT: 'Seleccionar'
  SERVICE: 'Servicio'
  SERVICE_LIST_ERROR: 'No hay servicios similares a la selección.'
  SERVICE_LIST_SUMMARY: 'Por favor, selecciona un Servicio'
  TIME: 'Horario'
  TO_CALENDAR: 'Revisar calendario, calendarizar'
  WHEN: 'Cuándo '
  WHERE: 'Cuándo '
  YOUR_DETAILS: 'Tus detalles'
  CANCEL_CONFIRMATION: 'Tu cita ha sido cancelada.'
  MOVE_BOOKINGS_MSG: 'Tu cita ha sido cancelada {{datetime}}'
  ERROR: {
    GENERIC: "Disculpa, algo está incorrecto. Por favor, intentalo de nuevo o llama a la sucursal de interés si el problema persite. "
    LOCATION_NOT_FOUND: "Disculpa, no reconocemos esa localización"
    MISSING_LOCATION: "Por favor entre la localización (dirección)"
    MISSING_POSTCODE: "Por favor ingrese un código postal"
    INVALID_POSTCODE: "Por favor ingrese un código postal válido"
    ITEM_NO_LONGER_AVAILABLE: "Disculpa, el horario que seleccionaste no está disponible. Por favor, intentalo de nuevo."
    FORM_INVALID: "Por favor completa todos los campos requeridos"
    GEOLOCATION_ERROR: "Disculpa, no podemos determinar esa localidad. Por favor busca una."
    EMPTY_BASKET_FOR_CHECKOUT: "No hay ningún producto en la cesta para proceder a la caja."
  }
};

(function (global, factory) {
   typeof exports === 'object' && typeof module !== 'undefined'
       && typeof require === 'function' ? factory(require('../moment')) :
   typeof define === 'function' && define.amd ? define(['moment'], factory) :
   factory(global.moment)
}(this, function (moment) { 'use strict';


    var monthsShortDot = 'ene._feb._mar._abr._may._jun._jul._ago._sep._oct._nov._dic.'.split('_'),
        monthsShort = 'ene_feb_mar_abr_may_jun_jul_ago_sep_oct_nov_dic'.split('_');

    var es = moment.defineLocale('es', {
        months : 'enero_febrero_marzo_abril_mayo_junio_julio_agosto_septiembre_octubre_noviembre_diciembre'.split('_'),
        monthsShort : function (m, format) {
            if (/-MMM-/.test(format)) {
                return monthsShort[m.month()];
            } else {
                return monthsShortDot[m.month()];
            }
        },
        weekdays : 'domingo_lunes_martes_miércoles_jueves_viernes_sábado'.split('_'),
        weekdaysShort : 'dom._lun._mar._mié._jue._vie._sáb.'.split('_'),
        weekdaysMin : 'do_lu_ma_mi_ju_vi_sá'.split('_'),
        longDateFormat : {
            LT : 'H:mm',
            LTS : 'H:mm:ss',
            L : 'DD/MM/YYYY',
            LL : 'D [de] MMMM [de] YYYY',
            LLL : 'D [de] MMMM [de] YYYY H:mm',
            LLLL : 'dddd, D [de] MMMM [de] YYYY H:mm'
        },
        calendar : {
            sameDay : function () {
                return '[hoy a la' + ((this.hours() !== 1) ? 's' : '') + '] LT';
            },
            nextDay : function () {
                return '[mañana a la' + ((this.hours() !== 1) ? 's' : '') + '] LT';
            },
            nextWeek : function () {
                return 'dddd [a la' + ((this.hours() !== 1) ? 's' : '') + '] LT';
            },
            lastDay : function () {
                return '[ayer a la' + ((this.hours() !== 1) ? 's' : '') + '] LT';
            },
            lastWeek : function () {
                return '[el] dddd [pasado a la' + ((this.hours() !== 1) ? 's' : '') + '] LT';
            },
            sameElse : 'L'
        },
        relativeTime : {
            future : 'en %s',
            past : 'hace %s',
            s : 'unos segundos',
            m : 'un minuto',
            mm : '%d minutos',
            h : 'una hora',
            hh : '%d horas',
            d : 'un día',
            dd : '%d días',
            M : 'un mes',
            MM : '%d meses',
            y : 'un año',
            yy : '%d años'
        },
        ordinalParse : /\d{1,2}º/,
        ordinal : '%dº',
        week : {
            dow : 1, // Monday is the first day of the week.
            doy : 4  // The week that contains Jan 4th is the first week of the year.
        }
    });

    return es;

}));
