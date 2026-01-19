package com.example;

import net.minecraft.world.phys.Vec3;
import net.minecraft.world.entity.Entity;

public class AimLogic {
    public static float[] getRotations(Entity player, Entity target) {
        // Position des yeux du joueur
        Vec3 eyePos = player.getEyePosition();
        // Position de la cible + offset tête
        double diffX = target.getX() - eyePos.x;
        double diffY = (target.getY() + 1.4) - eyePos.y; // 1.4 est souvent mieux que 1.62 pour le centre de la tête
        double diffZ = target.getZ() - eyePos.z;

        double diffXZ = Math.sqrt(diffX * diffX + diffZ * diffZ);

        float yaw = (float) Math.toDegrees(Math.atan2(diffZ, diffX)) - 90.0f;
        float pitch = (float) -Math.toDegrees(Math.atan2(diffY, diffXZ));

        return new float[]{yaw, pitch};
    }
}