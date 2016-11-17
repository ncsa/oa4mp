package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/10/16 at  10:22 AM
 */
public  class Thing {
      String value;

      public Thing(String value) {
          this.value = value;
      }

      public String getValue() {
          return value;
      }

      @Override
      public boolean equals(Object obj) {
          if(!(obj instanceof Thing)) return false;
          String targetValue = ((Thing) obj).getValue();
          if(getValue() == null && targetValue == null) return true;
          if(getValue() == null && targetValue != null) return false;
          if(getValue() != null && targetValue == null) return false;
          return getValue().equals(targetValue);
      }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" +
                "value='" + value + '\'' +
                ']';
    }
}
