package com.sansec.persistence.model;

import javax.persistence.*;

public class Seed {
    @Column(name = "s_id")
    private Integer sId;

    private String seed;

    /**
     * @return s_id
     */
    public Integer getsId() {
        return sId;
    }

    /**
     * @param sId
     */
    public void setsId(Integer sId) {
        this.sId = sId;
    }

    /**
     * @return seed
     */
    public String getSeed() {
        return seed;
    }

    /**
     * @param seed
     */
    public void setSeed(String seed) {
        this.seed = seed;
    }
}