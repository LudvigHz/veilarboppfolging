/**
 * Autogenerated by Avro
 *
 * DO NOT EDIT DIRECTLY
 */
package no.nav.paw.arbeidssokerregisteret.api.v1;

import org.apache.avro.generic.GenericArray;
import org.apache.avro.specific.SpecificData;
import org.apache.avro.util.Utf8;
import org.apache.avro.message.BinaryMessageEncoder;
import org.apache.avro.message.BinaryMessageDecoder;
import org.apache.avro.message.SchemaStore;

/** Inneholder metadata om en endring i arbeidssøkerregisteret. */
@org.apache.avro.specific.AvroGenerated
public class Metadata extends org.apache.avro.specific.SpecificRecordBase implements org.apache.avro.specific.SpecificRecord {
  private static final long serialVersionUID = 4638426549960298156L;


  public static final org.apache.avro.Schema SCHEMA$ = new org.apache.avro.Schema.Parser().parse("{\"type\":\"record\",\"name\":\"Metadata\",\"namespace\":\"no.nav.paw.arbeidssokerregisteret.api.v1\",\"doc\":\"Inneholder metadata om en endring i arbeidssøkerregisteret.\",\"fields\":[{\"name\":\"tidspunkt\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"},\"doc\":\"Tidspunkt for endringen.\"},{\"name\":\"utfoertAv\",\"type\":{\"type\":\"record\",\"name\":\"Bruker\",\"doc\":\"En bruker er en person eller et system. Personer kan være sluttbrukere eller veiledere.\",\"fields\":[{\"name\":\"type\",\"type\":{\"type\":\"enum\",\"name\":\"BrukerType\",\"symbols\":[\"UKJENT_VERDI\",\"UDEFINERT\",\"VEILEDER\",\"SYSTEM\",\"SLUTTBRUKER\"],\"default\":\"UKJENT_VERDI\"},\"doc\":\"Angir hvilken type bruker det er snakk om\"},{\"name\":\"id\",\"type\":\"string\",\"doc\":\"Brukerens identifikator.\\nFor sluttbruker er dette typisk fødselsnummer eller D-nummer.\\nFor system vil det rett og slett være navnet på et system, eventuelt med versjonsnummer i tillegg (APP_NAVN:VERSJON).\\nFor veileder vil det være NAV identen til veilederen.\"}]}},{\"name\":\"kilde\",\"type\":\"string\",\"doc\":\"Navn på systemet som utførte endringen eller ble benyttet til å utføre endringen.\"},{\"name\":\"aarsak\",\"type\":\"string\",\"doc\":\"Aarasek til endringen. Feks \\\"Flyttet ut av landet\\\" eller lignende.\"},{\"name\":\"tidspunktFraKilde\",\"type\":[\"null\",{\"type\":\"record\",\"name\":\"TidspunktFraKilde\",\"fields\":[{\"name\":\"tidspunkt\",\"type\":{\"type\":\"long\",\"logicalType\":\"timestamp-millis\"},\"doc\":\"Tidspunktet melding ideelt sett skulle vært registert på.\"},{\"name\":\"avviksType\",\"type\":{\"type\":\"enum\",\"name\":\"AvviksType\",\"doc\":\"Ukjent verdi settes aldri direkte, men brukes som standardverdi og\\nfor å indikere at en verdi er ukjent for mottaker av melding, dvs at\\nat den er satt til en verdi som ikke er definert i Avro-skjemaet til mottaker.\\n\\nFORSINKELSE - Grunnen til avvik mellom kilde og register er generell forsinkelse\\n\\t\\t\\t\\t som oppstår i asynkrone systemer.\\n\\nRETTING - \\tGrunnen til avvik mellom kilde og register er at en feil i kilde er rettet\\n             med virking bakover i tid.\",\"symbols\":[\"UKJENT_VERDI\",\"FORSINKELSE\",\"RETTING\"],\"default\":\"UKJENT_VERDI\"},\"doc\":\"Årsaken til til avvik i tid mellom kilde og register.\"}]}],\"doc\":\"Avvik i tid mellom kilde og register.\",\"default\":null}]}");
  public static org.apache.avro.Schema getClassSchema() { return SCHEMA$; }

  private static final SpecificData MODEL$ = new SpecificData();
  static {
    MODEL$.addLogicalTypeConversion(new org.apache.avro.data.TimeConversions.TimestampMillisConversion());
  }

  private static final BinaryMessageEncoder<Metadata> ENCODER =
      new BinaryMessageEncoder<>(MODEL$, SCHEMA$);

  private static final BinaryMessageDecoder<Metadata> DECODER =
      new BinaryMessageDecoder<>(MODEL$, SCHEMA$);

  /**
   * Return the BinaryMessageEncoder instance used by this class.
   * @return the message encoder used by this class
   */
  public static BinaryMessageEncoder<Metadata> getEncoder() {
    return ENCODER;
  }

  /**
   * Return the BinaryMessageDecoder instance used by this class.
   * @return the message decoder used by this class
   */
  public static BinaryMessageDecoder<Metadata> getDecoder() {
    return DECODER;
  }

  /**
   * Create a new BinaryMessageDecoder instance for this class that uses the specified {@link SchemaStore}.
   * @param resolver a {@link SchemaStore} used to find schemas by fingerprint
   * @return a BinaryMessageDecoder instance for this class backed by the given SchemaStore
   */
  public static BinaryMessageDecoder<Metadata> createDecoder(SchemaStore resolver) {
    return new BinaryMessageDecoder<>(MODEL$, SCHEMA$, resolver);
  }

  /**
   * Serializes this Metadata to a ByteBuffer.
   * @return a buffer holding the serialized data for this instance
   * @throws java.io.IOException if this instance could not be serialized
   */
  public java.nio.ByteBuffer toByteBuffer() throws java.io.IOException {
    return ENCODER.encode(this);
  }

  /**
   * Deserializes a Metadata from a ByteBuffer.
   * @param b a byte buffer holding serialized data for an instance of this class
   * @return a Metadata instance decoded from the given buffer
   * @throws java.io.IOException if the given bytes could not be deserialized into an instance of this class
   */
  public static Metadata fromByteBuffer(
      java.nio.ByteBuffer b) throws java.io.IOException {
    return DECODER.decode(b);
  }

  /** Tidspunkt for endringen. */
  private java.time.Instant tidspunkt;
  private no.nav.paw.arbeidssokerregisteret.api.v1.Bruker utfoertAv;
  /** Navn på systemet som utførte endringen eller ble benyttet til å utføre endringen. */
  private java.lang.CharSequence kilde;
  /** Aarasek til endringen. Feks "Flyttet ut av landet" eller lignende. */
  private java.lang.CharSequence aarsak;
  /** Avvik i tid mellom kilde og register. */
  private no.nav.paw.arbeidssokerregisteret.api.v1.TidspunktFraKilde tidspunktFraKilde;

  /**
   * Default constructor.  Note that this does not initialize fields
   * to their default values from the schema.  If that is desired then
   * one should use <code>newBuilder()</code>.
   */
  public Metadata() {}

  /**
   * All-args constructor.
   * @param tidspunkt Tidspunkt for endringen.
   * @param utfoertAv The new value for utfoertAv
   * @param kilde Navn på systemet som utførte endringen eller ble benyttet til å utføre endringen.
   * @param aarsak Aarasek til endringen. Feks "Flyttet ut av landet" eller lignende.
   * @param tidspunktFraKilde Avvik i tid mellom kilde og register.
   */
  public Metadata(java.time.Instant tidspunkt, no.nav.paw.arbeidssokerregisteret.api.v1.Bruker utfoertAv, java.lang.CharSequence kilde, java.lang.CharSequence aarsak, no.nav.paw.arbeidssokerregisteret.api.v1.TidspunktFraKilde tidspunktFraKilde) {
    this.tidspunkt = tidspunkt.truncatedTo(java.time.temporal.ChronoUnit.MILLIS);
    this.utfoertAv = utfoertAv;
    this.kilde = kilde;
    this.aarsak = aarsak;
    this.tidspunktFraKilde = tidspunktFraKilde;
  }

  @Override
  public org.apache.avro.specific.SpecificData getSpecificData() { return MODEL$; }

  @Override
  public org.apache.avro.Schema getSchema() { return SCHEMA$; }

  // Used by DatumWriter.  Applications should not call.
  @Override
  public java.lang.Object get(int field$) {
    switch (field$) {
    case 0: return tidspunkt;
    case 1: return utfoertAv;
    case 2: return kilde;
    case 3: return aarsak;
    case 4: return tidspunktFraKilde;
    default: throw new IndexOutOfBoundsException("Invalid index: " + field$);
    }
  }

  private static final org.apache.avro.Conversion<?>[] conversions =
      new org.apache.avro.Conversion<?>[] {
      new org.apache.avro.data.TimeConversions.TimestampMillisConversion(),
      null,
      null,
      null,
      null,
      null
  };

  @Override
  public org.apache.avro.Conversion<?> getConversion(int field) {
    return conversions[field];
  }

  // Used by DatumReader.  Applications should not call.
  @Override
  @SuppressWarnings(value="unchecked")
  public void put(int field$, java.lang.Object value$) {
    switch (field$) {
    case 0: tidspunkt = (java.time.Instant)value$; break;
    case 1: utfoertAv = (no.nav.paw.arbeidssokerregisteret.api.v1.Bruker)value$; break;
    case 2: kilde = (java.lang.CharSequence)value$; break;
    case 3: aarsak = (java.lang.CharSequence)value$; break;
    case 4: tidspunktFraKilde = (no.nav.paw.arbeidssokerregisteret.api.v1.TidspunktFraKilde)value$; break;
    default: throw new IndexOutOfBoundsException("Invalid index: " + field$);
    }
  }

  /**
   * Gets the value of the 'tidspunkt' field.
   * @return Tidspunkt for endringen.
   */
  public java.time.Instant getTidspunkt() {
    return tidspunkt;
  }


  /**
   * Sets the value of the 'tidspunkt' field.
   * Tidspunkt for endringen.
   * @param value the value to set.
   */
  public void setTidspunkt(java.time.Instant value) {
    this.tidspunkt = value.truncatedTo(java.time.temporal.ChronoUnit.MILLIS);
  }

  /**
   * Gets the value of the 'utfoertAv' field.
   * @return The value of the 'utfoertAv' field.
   */
  public no.nav.paw.arbeidssokerregisteret.api.v1.Bruker getUtfoertAv() {
    return utfoertAv;
  }


  /**
   * Sets the value of the 'utfoertAv' field.
   * @param value the value to set.
   */
  public void setUtfoertAv(no.nav.paw.arbeidssokerregisteret.api.v1.Bruker value) {
    this.utfoertAv = value;
  }

  /**
   * Gets the value of the 'kilde' field.
   * @return Navn på systemet som utførte endringen eller ble benyttet til å utføre endringen.
   */
  public java.lang.CharSequence getKilde() {
    return kilde;
  }


  /**
   * Sets the value of the 'kilde' field.
   * Navn på systemet som utførte endringen eller ble benyttet til å utføre endringen.
   * @param value the value to set.
   */
  public void setKilde(java.lang.CharSequence value) {
    this.kilde = value;
  }

  /**
   * Gets the value of the 'aarsak' field.
   * @return Aarasek til endringen. Feks "Flyttet ut av landet" eller lignende.
   */
  public java.lang.CharSequence getAarsak() {
    return aarsak;
  }


  /**
   * Sets the value of the 'aarsak' field.
   * Aarasek til endringen. Feks "Flyttet ut av landet" eller lignende.
   * @param value the value to set.
   */
  public void setAarsak(java.lang.CharSequence value) {
    this.aarsak = value;
  }

  /**
   * Gets the value of the 'tidspunktFraKilde' field.
   * @return Avvik i tid mellom kilde og register.
   */
  public no.nav.paw.arbeidssokerregisteret.api.v1.TidspunktFraKilde getTidspunktFraKilde() {
    return tidspunktFraKilde;
  }


  /**
   * Sets the value of the 'tidspunktFraKilde' field.
   * Avvik i tid mellom kilde og register.
   * @param value the value to set.
   */
  public void setTidspunktFraKilde(no.nav.paw.arbeidssokerregisteret.api.v1.TidspunktFraKilde value) {
    this.tidspunktFraKilde = value;
  }

  /**
   * Creates a new Metadata RecordBuilder.
   * @return A new Metadata RecordBuilder
   */
  public static no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder newBuilder() {
    return new no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder();
  }

  /**
   * Creates a new Metadata RecordBuilder by copying an existing Builder.
   * @param other The existing builder to copy.
   * @return A new Metadata RecordBuilder
   */
  public static no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder newBuilder(no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder other) {
    if (other == null) {
      return new no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder();
    } else {
      return new no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder(other);
    }
  }

  /**
   * Creates a new Metadata RecordBuilder by copying an existing Metadata instance.
   * @param other The existing instance to copy.
   * @return A new Metadata RecordBuilder
   */
  public static no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder newBuilder(no.nav.paw.arbeidssokerregisteret.api.v1.Metadata other) {
    if (other == null) {
      return new no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder();
    } else {
      return new no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder(other);
    }
  }

  /**
   * RecordBuilder for Metadata instances.
   */
  @org.apache.avro.specific.AvroGenerated
  public static class Builder extends org.apache.avro.specific.SpecificRecordBuilderBase<Metadata>
    implements org.apache.avro.data.RecordBuilder<Metadata> {

    /** Tidspunkt for endringen. */
    private java.time.Instant tidspunkt;
    private no.nav.paw.arbeidssokerregisteret.api.v1.Bruker utfoertAv;
    private no.nav.paw.arbeidssokerregisteret.api.v1.Bruker.Builder utfoertAvBuilder;
    /** Navn på systemet som utførte endringen eller ble benyttet til å utføre endringen. */
    private java.lang.CharSequence kilde;
    /** Aarasek til endringen. Feks "Flyttet ut av landet" eller lignende. */
    private java.lang.CharSequence aarsak;
    /** Avvik i tid mellom kilde og register. */
    private no.nav.paw.arbeidssokerregisteret.api.v1.TidspunktFraKilde tidspunktFraKilde;
    private no.nav.paw.arbeidssokerregisteret.api.v1.TidspunktFraKilde.Builder tidspunktFraKildeBuilder;

    /** Creates a new Builder */
    private Builder() {
      super(SCHEMA$, MODEL$);
    }

    /**
     * Creates a Builder by copying an existing Builder.
     * @param other The existing Builder to copy.
     */
    private Builder(no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder other) {
      super(other);
      if (isValidValue(fields()[0], other.tidspunkt)) {
        this.tidspunkt = data().deepCopy(fields()[0].schema(), other.tidspunkt);
        fieldSetFlags()[0] = other.fieldSetFlags()[0];
      }
      if (isValidValue(fields()[1], other.utfoertAv)) {
        this.utfoertAv = data().deepCopy(fields()[1].schema(), other.utfoertAv);
        fieldSetFlags()[1] = other.fieldSetFlags()[1];
      }
      if (other.hasUtfoertAvBuilder()) {
        this.utfoertAvBuilder = no.nav.paw.arbeidssokerregisteret.api.v1.Bruker.newBuilder(other.getUtfoertAvBuilder());
      }
      if (isValidValue(fields()[2], other.kilde)) {
        this.kilde = data().deepCopy(fields()[2].schema(), other.kilde);
        fieldSetFlags()[2] = other.fieldSetFlags()[2];
      }
      if (isValidValue(fields()[3], other.aarsak)) {
        this.aarsak = data().deepCopy(fields()[3].schema(), other.aarsak);
        fieldSetFlags()[3] = other.fieldSetFlags()[3];
      }
      if (isValidValue(fields()[4], other.tidspunktFraKilde)) {
        this.tidspunktFraKilde = data().deepCopy(fields()[4].schema(), other.tidspunktFraKilde);
        fieldSetFlags()[4] = other.fieldSetFlags()[4];
      }
      if (other.hasTidspunktFraKildeBuilder()) {
        this.tidspunktFraKildeBuilder = no.nav.paw.arbeidssokerregisteret.api.v1.TidspunktFraKilde.newBuilder(other.getTidspunktFraKildeBuilder());
      }
    }

    /**
     * Creates a Builder by copying an existing Metadata instance
     * @param other The existing instance to copy.
     */
    private Builder(no.nav.paw.arbeidssokerregisteret.api.v1.Metadata other) {
      super(SCHEMA$, MODEL$);
      if (isValidValue(fields()[0], other.tidspunkt)) {
        this.tidspunkt = data().deepCopy(fields()[0].schema(), other.tidspunkt);
        fieldSetFlags()[0] = true;
      }
      if (isValidValue(fields()[1], other.utfoertAv)) {
        this.utfoertAv = data().deepCopy(fields()[1].schema(), other.utfoertAv);
        fieldSetFlags()[1] = true;
      }
      this.utfoertAvBuilder = null;
      if (isValidValue(fields()[2], other.kilde)) {
        this.kilde = data().deepCopy(fields()[2].schema(), other.kilde);
        fieldSetFlags()[2] = true;
      }
      if (isValidValue(fields()[3], other.aarsak)) {
        this.aarsak = data().deepCopy(fields()[3].schema(), other.aarsak);
        fieldSetFlags()[3] = true;
      }
      if (isValidValue(fields()[4], other.tidspunktFraKilde)) {
        this.tidspunktFraKilde = data().deepCopy(fields()[4].schema(), other.tidspunktFraKilde);
        fieldSetFlags()[4] = true;
      }
      this.tidspunktFraKildeBuilder = null;
    }

    /**
      * Gets the value of the 'tidspunkt' field.
      * Tidspunkt for endringen.
      * @return The value.
      */
    public java.time.Instant getTidspunkt() {
      return tidspunkt;
    }


    /**
      * Sets the value of the 'tidspunkt' field.
      * Tidspunkt for endringen.
      * @param value The value of 'tidspunkt'.
      * @return This builder.
      */
    public no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder setTidspunkt(java.time.Instant value) {
      validate(fields()[0], value);
      this.tidspunkt = value.truncatedTo(java.time.temporal.ChronoUnit.MILLIS);
      fieldSetFlags()[0] = true;
      return this;
    }

    /**
      * Checks whether the 'tidspunkt' field has been set.
      * Tidspunkt for endringen.
      * @return True if the 'tidspunkt' field has been set, false otherwise.
      */
    public boolean hasTidspunkt() {
      return fieldSetFlags()[0];
    }


    /**
      * Clears the value of the 'tidspunkt' field.
      * Tidspunkt for endringen.
      * @return This builder.
      */
    public no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder clearTidspunkt() {
      fieldSetFlags()[0] = false;
      return this;
    }

    /**
      * Gets the value of the 'utfoertAv' field.
      * @return The value.
      */
    public no.nav.paw.arbeidssokerregisteret.api.v1.Bruker getUtfoertAv() {
      return utfoertAv;
    }


    /**
      * Sets the value of the 'utfoertAv' field.
      * @param value The value of 'utfoertAv'.
      * @return This builder.
      */
    public no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder setUtfoertAv(no.nav.paw.arbeidssokerregisteret.api.v1.Bruker value) {
      validate(fields()[1], value);
      this.utfoertAvBuilder = null;
      this.utfoertAv = value;
      fieldSetFlags()[1] = true;
      return this;
    }

    /**
      * Checks whether the 'utfoertAv' field has been set.
      * @return True if the 'utfoertAv' field has been set, false otherwise.
      */
    public boolean hasUtfoertAv() {
      return fieldSetFlags()[1];
    }

    /**
     * Gets the Builder instance for the 'utfoertAv' field and creates one if it doesn't exist yet.
     * @return This builder.
     */
    public no.nav.paw.arbeidssokerregisteret.api.v1.Bruker.Builder getUtfoertAvBuilder() {
      if (utfoertAvBuilder == null) {
        if (hasUtfoertAv()) {
          setUtfoertAvBuilder(no.nav.paw.arbeidssokerregisteret.api.v1.Bruker.newBuilder(utfoertAv));
        } else {
          setUtfoertAvBuilder(no.nav.paw.arbeidssokerregisteret.api.v1.Bruker.newBuilder());
        }
      }
      return utfoertAvBuilder;
    }

    /**
     * Sets the Builder instance for the 'utfoertAv' field
     * @param value The builder instance that must be set.
     * @return This builder.
     */

    public no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder setUtfoertAvBuilder(no.nav.paw.arbeidssokerregisteret.api.v1.Bruker.Builder value) {
      clearUtfoertAv();
      utfoertAvBuilder = value;
      return this;
    }

    /**
     * Checks whether the 'utfoertAv' field has an active Builder instance
     * @return True if the 'utfoertAv' field has an active Builder instance
     */
    public boolean hasUtfoertAvBuilder() {
      return utfoertAvBuilder != null;
    }

    /**
      * Clears the value of the 'utfoertAv' field.
      * @return This builder.
      */
    public no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder clearUtfoertAv() {
      utfoertAv = null;
      utfoertAvBuilder = null;
      fieldSetFlags()[1] = false;
      return this;
    }

    /**
      * Gets the value of the 'kilde' field.
      * Navn på systemet som utførte endringen eller ble benyttet til å utføre endringen.
      * @return The value.
      */
    public java.lang.CharSequence getKilde() {
      return kilde;
    }


    /**
      * Sets the value of the 'kilde' field.
      * Navn på systemet som utførte endringen eller ble benyttet til å utføre endringen.
      * @param value The value of 'kilde'.
      * @return This builder.
      */
    public no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder setKilde(java.lang.CharSequence value) {
      validate(fields()[2], value);
      this.kilde = value;
      fieldSetFlags()[2] = true;
      return this;
    }

    /**
      * Checks whether the 'kilde' field has been set.
      * Navn på systemet som utførte endringen eller ble benyttet til å utføre endringen.
      * @return True if the 'kilde' field has been set, false otherwise.
      */
    public boolean hasKilde() {
      return fieldSetFlags()[2];
    }


    /**
      * Clears the value of the 'kilde' field.
      * Navn på systemet som utførte endringen eller ble benyttet til å utføre endringen.
      * @return This builder.
      */
    public no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder clearKilde() {
      kilde = null;
      fieldSetFlags()[2] = false;
      return this;
    }

    /**
      * Gets the value of the 'aarsak' field.
      * Aarasek til endringen. Feks "Flyttet ut av landet" eller lignende.
      * @return The value.
      */
    public java.lang.CharSequence getAarsak() {
      return aarsak;
    }


    /**
      * Sets the value of the 'aarsak' field.
      * Aarasek til endringen. Feks "Flyttet ut av landet" eller lignende.
      * @param value The value of 'aarsak'.
      * @return This builder.
      */
    public no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder setAarsak(java.lang.CharSequence value) {
      validate(fields()[3], value);
      this.aarsak = value;
      fieldSetFlags()[3] = true;
      return this;
    }

    /**
      * Checks whether the 'aarsak' field has been set.
      * Aarasek til endringen. Feks "Flyttet ut av landet" eller lignende.
      * @return True if the 'aarsak' field has been set, false otherwise.
      */
    public boolean hasAarsak() {
      return fieldSetFlags()[3];
    }


    /**
      * Clears the value of the 'aarsak' field.
      * Aarasek til endringen. Feks "Flyttet ut av landet" eller lignende.
      * @return This builder.
      */
    public no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder clearAarsak() {
      aarsak = null;
      fieldSetFlags()[3] = false;
      return this;
    }

    /**
      * Gets the value of the 'tidspunktFraKilde' field.
      * Avvik i tid mellom kilde og register.
      * @return The value.
      */
    public no.nav.paw.arbeidssokerregisteret.api.v1.TidspunktFraKilde getTidspunktFraKilde() {
      return tidspunktFraKilde;
    }


    /**
      * Sets the value of the 'tidspunktFraKilde' field.
      * Avvik i tid mellom kilde og register.
      * @param value The value of 'tidspunktFraKilde'.
      * @return This builder.
      */
    public no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder setTidspunktFraKilde(no.nav.paw.arbeidssokerregisteret.api.v1.TidspunktFraKilde value) {
      validate(fields()[4], value);
      this.tidspunktFraKildeBuilder = null;
      this.tidspunktFraKilde = value;
      fieldSetFlags()[4] = true;
      return this;
    }

    /**
      * Checks whether the 'tidspunktFraKilde' field has been set.
      * Avvik i tid mellom kilde og register.
      * @return True if the 'tidspunktFraKilde' field has been set, false otherwise.
      */
    public boolean hasTidspunktFraKilde() {
      return fieldSetFlags()[4];
    }

    /**
     * Gets the Builder instance for the 'tidspunktFraKilde' field and creates one if it doesn't exist yet.
     * Avvik i tid mellom kilde og register.
     * @return This builder.
     */
    public no.nav.paw.arbeidssokerregisteret.api.v1.TidspunktFraKilde.Builder getTidspunktFraKildeBuilder() {
      if (tidspunktFraKildeBuilder == null) {
        if (hasTidspunktFraKilde()) {
          setTidspunktFraKildeBuilder(no.nav.paw.arbeidssokerregisteret.api.v1.TidspunktFraKilde.newBuilder(tidspunktFraKilde));
        } else {
          setTidspunktFraKildeBuilder(no.nav.paw.arbeidssokerregisteret.api.v1.TidspunktFraKilde.newBuilder());
        }
      }
      return tidspunktFraKildeBuilder;
    }

    /**
     * Sets the Builder instance for the 'tidspunktFraKilde' field
     * Avvik i tid mellom kilde og register.
     * @param value The builder instance that must be set.
     * @return This builder.
     */

    public no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder setTidspunktFraKildeBuilder(no.nav.paw.arbeidssokerregisteret.api.v1.TidspunktFraKilde.Builder value) {
      clearTidspunktFraKilde();
      tidspunktFraKildeBuilder = value;
      return this;
    }

    /**
     * Checks whether the 'tidspunktFraKilde' field has an active Builder instance
     * Avvik i tid mellom kilde og register.
     * @return True if the 'tidspunktFraKilde' field has an active Builder instance
     */
    public boolean hasTidspunktFraKildeBuilder() {
      return tidspunktFraKildeBuilder != null;
    }

    /**
      * Clears the value of the 'tidspunktFraKilde' field.
      * Avvik i tid mellom kilde og register.
      * @return This builder.
      */
    public no.nav.paw.arbeidssokerregisteret.api.v1.Metadata.Builder clearTidspunktFraKilde() {
      tidspunktFraKilde = null;
      tidspunktFraKildeBuilder = null;
      fieldSetFlags()[4] = false;
      return this;
    }

    @Override
    @SuppressWarnings("unchecked")
    public Metadata build() {
      try {
        Metadata record = new Metadata();
        record.tidspunkt = fieldSetFlags()[0] ? this.tidspunkt : (java.time.Instant) defaultValue(fields()[0]);
        if (utfoertAvBuilder != null) {
          try {
            record.utfoertAv = this.utfoertAvBuilder.build();
          } catch (org.apache.avro.AvroMissingFieldException e) {
            e.addParentField(record.getSchema().getField("utfoertAv"));
            throw e;
          }
        } else {
          record.utfoertAv = fieldSetFlags()[1] ? this.utfoertAv : (no.nav.paw.arbeidssokerregisteret.api.v1.Bruker) defaultValue(fields()[1]);
        }
        record.kilde = fieldSetFlags()[2] ? this.kilde : (java.lang.CharSequence) defaultValue(fields()[2]);
        record.aarsak = fieldSetFlags()[3] ? this.aarsak : (java.lang.CharSequence) defaultValue(fields()[3]);
        if (tidspunktFraKildeBuilder != null) {
          try {
            record.tidspunktFraKilde = this.tidspunktFraKildeBuilder.build();
          } catch (org.apache.avro.AvroMissingFieldException e) {
            e.addParentField(record.getSchema().getField("tidspunktFraKilde"));
            throw e;
          }
        } else {
          record.tidspunktFraKilde = fieldSetFlags()[4] ? this.tidspunktFraKilde : (no.nav.paw.arbeidssokerregisteret.api.v1.TidspunktFraKilde) defaultValue(fields()[4]);
        }
        return record;
      } catch (org.apache.avro.AvroMissingFieldException e) {
        throw e;
      } catch (java.lang.Exception e) {
        throw new org.apache.avro.AvroRuntimeException(e);
      }
    }
  }

  @SuppressWarnings("unchecked")
  private static final org.apache.avro.io.DatumWriter<Metadata>
    WRITER$ = (org.apache.avro.io.DatumWriter<Metadata>)MODEL$.createDatumWriter(SCHEMA$);

  @Override public void writeExternal(java.io.ObjectOutput out)
    throws java.io.IOException {
    WRITER$.write(this, SpecificData.getEncoder(out));
  }

  @SuppressWarnings("unchecked")
  private static final org.apache.avro.io.DatumReader<Metadata>
    READER$ = (org.apache.avro.io.DatumReader<Metadata>)MODEL$.createDatumReader(SCHEMA$);

  @Override public void readExternal(java.io.ObjectInput in)
    throws java.io.IOException {
    READER$.read(this, SpecificData.getDecoder(in));
  }

}










