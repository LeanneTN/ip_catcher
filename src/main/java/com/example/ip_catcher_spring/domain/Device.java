package com.example.ip_catcher_spring.domain;

public class Device {
    private String deviceName;
    private String deviceDescn;
    private int deviceIndex;

    public String getDeviceName() {
        return deviceName;
    }

    public void setDeviceName(String deviceName) {
        this.deviceName = deviceName;
    }

    public String getDeviceDescn() {
        return deviceDescn;
    }

    public void setDeviceDescn(String deviceDescn) {
        this.deviceDescn = deviceDescn;
    }

    public int getDeviceIndex() {
        return deviceIndex;
    }

    public void setDeviceIndex(int deviceIndex) {
        this.deviceIndex = deviceIndex;
    }
}
