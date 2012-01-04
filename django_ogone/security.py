import hashlib, logging

log = logging.getLogger('django_ogone')

class OgoneSignature(object):
    '''

    Signs the ogone parameters
    - all keys are in upper case
    - if no value is present the value is removed
    - parameters are sorted alphabetically
    - they limit the keys to a subsection of fields
      (not implemented in this api)
    - the secret is used between every parameter set and added to the end of
      the string

    >>> ogone = OgoneSignature(dict(d='a', a='b'), hash_method='sha512', secret='c')
    >>> sorted_data = ogone._sort_data(ogone.data)
    >>> sorted_data
    [('A', 'b'), ('D', 'a')]
    >>> pre_sign_string = ogone._merge_data(sorted_data)
    >>> pre_sign_string
    'A=bcD=ac'
    >>> signed = ogone._sign_string(pre_sign_string)
    >>> signed
    'B499539D7E0B2B1FB5CCFE9FFDDBAD1EDF345757C094443ED795662F879FB250EEEB22CBB2D2F3C129E2CAE735044CDB7B08397502204B0683EA370F6D76FB6A'
    >>> ogone.signature()
    'B499539D7E0B2B1FB5CCFE9FFDDBAD1EDF345757C094443ED795662F879FB250EEEB22CBB2D2F3C129E2CAE735044CDB7B08397502204B0683EA370F6D76FB6A'

    This is based on ogones docs
    Example shaOUT from ECOM advanced implementation

    >>> data = dict(acceptance=1234, amount=15, brand='VISA',
    ...             cardno='xxxxxxxxxxxx1111', currency='EUR', NCERROR=0,
    ...             orderId=12, payid=32100123, pm='CreditCard', status=9)
    >>> ogone = OgoneSignature(data, secret='Mysecretsig1875!?',
    ...                        hash_method='sha1')
    >>> sd = ogone._sort_data(ogone.data)
    >>> teststring = ogone._merge_data(sd)
    >>> signature = ogone._sign_string(teststring)
    >>> teststring
    'ACCEPTANCE=1234Mysecretsig1875!?AMOUNT=15Mysecretsig1875!?BRAND=VISAMysecretsig1875!?CARDNO=xxxxxxxxxxxx1111Mysecretsig1875!?CURRENCY=EURMysecretsig1875!?NCERROR=0Mysecretsig1875!?ORDERID=12Mysecretsig1875!?PAYID=32100123Mysecretsig1875!?PM=CreditCardMysecretsig1875!?STATUS=9Mysecretsig1875!?'
    >>> signature
    'B209960D5703DD1047F95A0F97655FFE5AC8BD52'

    This is based on ogones docs
    Example shaIn from ECOM advanced implementation
    >>> data = dict(amount=1500, currency='EUR', operation='RES',
    ...             orderID=1234, PSPID='MyPSPID')
    >>> ogone = OgoneSignature(data, secret='Mysecretsig1875!?',
    ...                        hash_method='sha1')
    >>> sd = ogone._sort_data(ogone.data)
    >>> teststring = ogone._merge_data(sd)
    >>> signature = ogone._sign_string(teststring)
    >>> teststring
    'AMOUNT=1500Mysecretsig1875!?CURRENCY=EURMysecretsig1875!?OPERATION=RESMysecretsig1875!?ORDERID=1234Mysecretsig1875!?PSPID=MyPSPIDMysecretsig1875!?'
    >>> signature
    'EB52902BCC4B50DC1250E5A7C1068ECF97751256'

    '''

    def __init__(self, data, hash_method, secret, encoding='utf8', out=False):
        assert hash_method in ['sha1', 'sha256', 'sha512']
        assert str(secret)

        self.data = data.copy()
        self.hash_method = hash_method
        self.secret = secret
        self.encoding = encoding
        self.out = out

    def _sort_data(self, data):
        # This code uppercases two times and is not well readable
        sorted_data = [(k.upper(), v) for k, v in data.items() \
                       if self._filter_data(k.upper(), v)]
        sorted_data.sort(key=lambda x: x, reverse=False)
        return sorted_data

    def _filter_data(self, k, v):
        SHA_IN_FILTER_WORDS = ['ACCEPTANCE', 'ACCEPTURL', 'ADDMATCH', 'ADDRMATCH', 'AIAGIATA', 'AIAIRNAME', 'AIAIRTAX', 'AIBOOKIND*XX*', 'AICARRIER*XX*', 'AICHDET', 'AICLASS*XX*', 'AICONJTI', 'AIDEPTCODE', 'AIDESTCITY*XX*', 'AIDESTCITYL*XX*', 'AIEXTRAPASNAME*XX*', 'AIEYCD', 'AIFLDATE*XX*', 'AIFLNUM*XX*', 'AIGLNUM', 'AIINVOICE', 'AIIRST', 'AIORCITY*XX*', 'AIORCITYL*XX*', 'AIPASNAME', 'AIPROJNUM', 'AISTOPOV*XX*', 'AITIDATE', 'AITINUM', 'AITINUML*XX*', 'AITYPCH', 'AIVATAMNT', 'AIVATAPPL', 'ALIAS', 'ALIASOPERATION', 'ALIASUSAGE', 'ALLOWCORRECTION', 'AMOUNT', 'AMOUNT*XX*', 'AMOUNTHTVA', 'AMOUNTTVA', 'BACKURL', 'BATCHID', 'BGCOLOR', 'BLVERNUM', 'BRAND', 'BRANDVISUAL', 'BUTTONBGCOLOR', 'BUTTONTXTCOLOR', 'CANCELURL', 'CARDNO', 'CATALOGURL', 'CAVV_3D', 'CAVVALGORITHM_3D', 'CERTID', 'CHECK_AAV', 'CIVILITY', 'CN', 'COM', 'COMPLUS', 'COSTCENTER', 'COSTCODE', 'CREDITCODE', 'CUID', 'CURRENCY', 'CVC', 'CVCFLAG', 'DATA', 'DATATYPE', 'DATEIN', 'DATEOUT', 'DECLINEURL', 'DEVICE', 'DISCOUNTRATE', 'DISPLAYMODE', 'ECI', 'ECI_3D', 'ECOM_BILLTO_POSTAL_CITY', 'ECOM_BILLTO_POSTAL_COUNTRYCODE', 'ECOM_BILLTO_POSTAL_NAME_FIRST', 'ECOM_BILLTO_POSTAL_NAME_LAST', 'ECOM_BILLTO_POSTAL_POSTALCODE', 'ECOM_BILLTO_POSTAL_STREET_LINE1', 'ECOM_BILLTO_POSTAL_STREET_LINE2', 'ECOM_BILLTO_POSTAL_STREET_NUMBER', 'ECOM_CONSUMERID', 'ECOM_CONSUMER_GENDER', 'ECOM_CONSUMEROGID', 'ECOM_CONSUMERORDERID', 'ECOM_CONSUMERUSERALIAS', 'ECOM_CONSUMERUSERPWD', 'ECOM_CONSUMERUSERID', 'ECOM_PAYMENT_CARD_EXPDATE_MONTH', 'ECOM_PAYMENT_CARD_EXPDATE_YEAR', 'ECOM_PAYMENT_CARD_NAME', 'ECOM_PAYMENT_CARD_VERIFICATION', 'ECOM_SHIPTO_COMPANY', 'ECOM_SHIPTO_DOB', 'ECOM_SHIPTO_ONLINE_EMAIL', 'ECOM_SHIPTO_POSTAL_CITY', 'ECOM_SHIPTO_POSTAL_COUNTRYCODE', 'ECOM_SHIPTO_POSTAL_NAME_FIRST', 'ECOM_SHIPTO_POSTAL_NAME_LAST', 'ECOM_SHIPTO_POSTAL_NAME_PREFIX', 'ECOM_SHIPTO_POSTAL_POSTALCODE', 'ECOM_SHIPTO_POSTAL_STREET_LINE1', 'ECOM_SHIPTO_POSTAL_STREET_LINE2', 'ECOM_SHIPTO_POSTAL_STREET_NUMBER', 'ECOM_SHIPTO_TELECOM_FAX_NUMBER', 'ECOM_SHIPTO_TELECOM_PHONE_NUMBER', 'ECOM_SHIPTO_TVA', 'ED', 'EMAIL', 'EXCEPTIONURL', 'EXCLPMLIST', 'EXECUTIONDATE*XX*', 'FACEXCL*XX*', 'FACTOTAL*XX*', 'FIRSTCALL', 'FLAG3D', 'FONTTYPE', 'FORCECODE1', 'FORCECODE2', 'FORCECODEHASH', 'FORCEPROCESS', 'FORCETP', 'GENERIC_BL', 'GIROPAY_ACCOUNT_NUMBER', 'GIROPAY_BLZ', 'GIROPAY_OWNER_NAME', 'GLOBORDERID', 'GUID', 'HDFONTTYPE', 'HDTBLBGCOLOR', 'HDTBLTXTCOLOR', 'HEIGHTFRAME', 'HOMEURL', 'HTTP_ACCEPT', 'HTTP_USER_AGENT', 'INCLUDE_BIN', 'INCLUDE_COUNTRIES', 'INVDATE', 'INVDISCOUNT', 'INVLEVEL', 'INVORDERID', 'ISSUERID', 'IST_MOBILE', 'ITEM_COUNT', 'ITEMATTRIBUTES*XX*', 'ITEMCATEGORY*XX*', 'ITEMCOMMENTS*XX*', 'ITEMDESC*XX*', 'ITEMDISCOUNT*XX*', 'ITEMID*XX*', 'ITEMNAME*XX*', 'ITEMPRICE*XX*', 'ITEMQUANT*XX*', 'ITEMQUANTORIG*XX*', 'ITEMUNITOFMEASURE*XX*', 'ITEMVAT*XX*', 'ITEMVATCODE*XX*', 'ITEMWEIGHT*XX*', 'LANGUAGE', 'LEVEL1AUTHCPC', 'LIDEXCL*XX*', 'LIMITCLIENTSCRIPTUSAGE', 'LINE_REF', 'LINE_REF1', 'LINE_REF2', 'LINE_REF3', 'LINE_REF4', 'LINE_REF5', 'LINE_REF6', 'LIST_BIN', 'LIST_COUNTRIES', 'LOGO', 'MAXITEMQUANT*XX*', 'MERCHANTID', 'MODE', 'MTIME', 'MVER', 'NETAMOUNT', 'OPERATION', 'ORDERID', 'ORDERSHIPCOST', 'ORDERSHIPTAX', 'ORDERSHIPTAXCODE', 'ORIG', 'OR_INVORDERID', 'OR_ORDERID', 'OWNERADDRESS', 'OWNERADDRESS2', 'OWNERCTY', 'OWNERTELNO', 'OWNERTOWN', 'OWNERZIP', 'PAIDAMOUNT', 'PARAMPLUS', 'PARAMVAR', 'PAYID', 'PAYMETHOD', 'PM', 'PMLIST', 'PMLISTPMLISTTYPE', 'PMLISTTYPE', 'PMLISTTYPEPMLIST', 'PMTYPE', 'POPUP', 'POST', 'PSPID', 'PSWD', 'REF', 'REFER', 'REFID', 'REFKIND', 'REF_CUSTOMERID', 'REF_CUSTOMERREF', 'REGISTRED', 'REMOTE_ADDR', 'REQGENFIELDS', 'RTIMEOUT', 'RTIMEOUTREQUESTEDTIMEOUT', 'SCORINGCLIENT', 'SETT_BATCH', 'SID', 'STATUS_3D', 'SUBSCRIPTION_ID', 'SUB_AM', 'SUB_AMOUNT', 'SUB_COM', 'SUB_COMMENT', 'SUB_CUR', 'SUB_ENDDATE', 'SUB_ORDERID', 'SUB_PERIOD_MOMENT', 'SUB_PERIOD_MOMENT_M', 'SUB_PERIOD_MOMENT_WW', 'SUB_PERIOD_NUMBER', 'SUB_PERIOD_NUMBER_D', 'SUB_PERIOD_NUMBER_M', 'SUB_PERIOD_NUMBER_WW', 'SUB_PERIOD_UNIT', 'SUB_STARTDATE', 'SUB_STATUS', 'TAAL', 'TAXINCLUDED*XX*', 'TBLBGCOLOR', 'TBLTXTCOLOR', 'TID', 'TITLE', 'TOTALAMOUNT', 'TP', 'TRACK2', 'TXTBADDR2', 'TXTCOLOR', 'TXTOKEN', 'TXTOKENTXTOKENPAYPAL', 'TYPE_COUNTRY', 'UCAF_AUTHENTICATION_DATA', 'UCAF_PAYMENT_CARD_CVC2', 'UCAF_PAYMENT_CARD_EXPDATE_MONTH', 'UCAF_PAYMENT_CARD_EXPDATE_YEAR', 'UCAF_PAYMENT_CARD_NUMBER', 'USERID', 'USERTYPE', 'VERSION', 'WBTU_MSISDN', 'WBTU_ORDERID', 'WEIGHTUNIT', 'WIN3DS', 'WITHROOT']
        SHA_OUT_FILTER_WORDS = ['AAVADDRESS', 'AAVCHECK', 'AAVZIP', 'ACCEPTANCE', 'ALIAS', 'AMOUNT', 'BIN', 'BRAND', 'CARDNO', 'CCCTY', 'CN', 'COMPLUS', 'CREATION_STATUS', 'CURRENCY', 'CVCCHECK', 'DCC_COMMPERCENTAGE', 'DCC_CONVAMOUNT', 'DCC_CONVCCY', 'DCC_EXCHRATE', 'DCC_EXCHRATESOURCE', 'DCC_EXCHRATETS', 'DCC_INDICATOR', 'DCC_MARGINPERCENTAGE', 'DCC_VALIDHOURS', 'DIGESTCARDNO', 'ECI', 'ED', 'ENCCARDNO', 'IP', 'IPCTY', 'NBREMAILUSAGE', 'NBRIPUSAGE', 'NBRIPUSAGE_ALLTX', 'NBRUSAGE', 'NCERROR', 'ORDERID', 'PAYID', 'PM', 'SCO_CATEGORY', 'SCORING', 'STATUS', 'SUBBRAND', 'SUBSCRIPTION_ID', 'TRXDATE', 'VC']

        valid = True
        if v == '' or v is None:
            valid = False

        if not self.out and k.upper() not in SHA_IN_FILTER_WORDS: valid = False
        if self.out and k.upper() not in SHA_OUT_FILTER_WORDS: valid = False

        if k == 'SHASIGN':
            valid = False
        return valid

    def _merge_data(self, data):
        pairs = ['%s=%s' % (k, v) for k, v in data]
        pre_sign_string = self.secret.join(pairs) + self.secret
        return pre_sign_string.encode(self.encoding)

    def _sign_string(self, pre_sign_string):
        hashmethod = getattr(hashlib, self.hash_method)
        signed = hashmethod(pre_sign_string).hexdigest().upper()
        return signed

    def signature(self):
        log.debug('Making signature for data: %s', self.data)
        
        sorted_data = self._sort_data(self.data)
        log.debug('Sorted data: %s', sorted_data)
        
        pre_sign_string = self._merge_data(sorted_data)
        log.debug('String to sign: (normal) %s', pre_sign_string)
        
        signed = self._sign_string(pre_sign_string)
        log.debug('Signed data: %s', signed)
                
        return signed

    def __unicode__(self):
        return self.signature()


