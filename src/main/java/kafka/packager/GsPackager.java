package kafka.packager;

import org.jpos.iso.*;

/**
 * Created by A_Tofigh at 09/21/2024
 */
public class GsPackager extends ISOBasePackager {
    protected ISOFieldPackager fld[] = {
            /*000*/ new IFA_NUMERIC(4, "Message Type Indicator"),
            /*001*/ new IFA_BITMAP(16, "Bitmap"),
            /*002*/ new IF_CHAR(6, "traceNo"),
            /*003*/new IFA_NUMERIC(6, "PROCESSING CODE"),

            /*004*/ new IF_CHAR(4, "gs_id"),
            /*005*/ new IF_CHAR(2, "pt_id"),
            /*006*/ new IF_CHAR(2, "nozzle_id"),
            /*007*/ new IF_CHAR(2, "zone_id"),
            /*008*/ new IF_CHAR(4, "city_id"),
            /*009*/ new IFA_LLCHAR(99, "gs_alias"),
            /*010*/ new IF_CHAR(2, "op_id"), // 01, 02 ,...
            /*011*/ new IF_CHAR(14, "start-transaction-Date-time"), //yyyyMMddHHmmss
            /*012*/ new IF_CHAR(14, "end-transaction-Date-time"), //yyyyMMddHHmmss
            /*013*/ new IFA_LLCHAR(99, "shift_no"), //yyyyMMddxx xx=01,02,...
            /*014*/ new IF_CHAR(2, "daily_no"), // max 31 - cutoff
            /*015*/ new IF_CHAR(12, "fuel_ttc"),
            /*016*/ new IF_CHAR(6, "fuel_duration_time"), //in second
            /*017*/ new IF_CHAR(2, "fuel_type"),
            /*018*/ new IF_CHAR(1, "trans_type"),
            /*019*/ new IFA_LLCHAR(99, "userCard_id"),
            /*020*/ new IFA_LLCHAR(99, "fuel_sam_id"),
            /*021*/ new IFA_LLCHAR(99, "dev_serial_id"),
            /*022*/ new IF_CHAR(12, "total_litter_100"),
            /*023*/ new IF_CHAR(12, "extra_litter_100"),
            /*024*/new IF_CHAR(12, "total_cost"),
            /*025*/new IF_CHAR(12, "price_unit"),
            /*026*/ new IF_CHAR(1, "fueling_status"),
            /*027*/new IFA_LLCHAR(99, "e_totalizer"),  //?
            /*028*/new IFA_LLLCHAR(999, "quota"),
            /*029*/new IF_CHAR(1, "RESERVED PRIVATE"),
            /*030*/ new IFA_NUMERIC(16, "SECURITY RELATED CONTROL INFORMATION"),
            /*031*/ new IFA_LLLCHAR(120, "ADDITIONAL AMOUNTS"),
            /*032*/ new IFA_LLLCHAR(999, "ADDITIONAL DATA"),
            /*033*/ new IFA_LLLLCHAR(9999, "INQUIRY RESPONSE"),
            /*034*/ new IFA_LLLCHAR(999, "RESERVED NATIONAL"),
            /*035*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*036*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*037*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*038*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*039*/ new IF_CHAR(2, "responseCode"),
            /*040*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*041*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*042*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*043*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*044*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*045*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*046*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*047*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*048*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*049*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*050*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*051*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*052*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*053*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*054*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*055*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*056*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*057*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*058*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*059*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*060*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*061*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*062*/ new IFA_LLLCHAR(999, "RESERVED PRIVATE"),
            /*063*/ new IFA_BINARY(32, "EXCHANGED KEY"),
            /*064*/ new IFA_BINARY(16, "MESSAGE AUTHENTICATION CODE FIELD")
    };

    public GsPackager() {
        super();
        setFieldPackager(fld);
    }
}
